/****************************************************************************
 * drivers/binder/binder_trans.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#define LOG_TAG "BinderTrans"

#include <nuttx/config.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <debug.h>
#include <sched.h>
#include <nuttx/fs/fs.h>
#include <nuttx/android/binder.h>
#include <nuttx/mutex.h>
#include <nuttx/nuttx.h>
#include <nuttx/kmalloc.h>
#include <nuttx/semaphore.h>
#include <nuttx/sched.h>
#include <nuttx/wqueue.h>
#include "binder_internal.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define to_flat_binder_object(hdr) \
  container_of(hdr, struct flat_binder_object, hdr)

#define to_binder_fd_object(hdr) \
  container_of(hdr, struct binder_fd_object, hdr)

#define to_binder_buffer_object(hdr) \
  container_of(hdr, struct binder_buffer_object, hdr)

#define to_binder_fd_array_object(hdr) \
  container_of(hdr, struct binder_fd_array_object, hdr)

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static bool binder_supported_policy(pid_t pid)
{
  int policy = nxsched_get_scheduler(pid);

  return policy == SCHED_FIFO || policy == SCHED_RR ||
         policy == SCHED_SPORADIC;
}

static uid_t geteuid_bypid(pid_t pid)
{
#ifdef CONFIG_SCHED_USER_IDENTITY
  /* We have effective UID support, then give the effective UID. */

  FAR struct tcb_s *tcb = nxsched_get_tcb(pid);
  FAR struct task_group_s *rgroup = tcb->group;

  DEBUGASSERT(rgroup != NULL);
  return rgroup->tg_euid;
#else
  /* Return user identity 'root' with a uid value of 0. */

  return 0;
#endif
}

/****************************************************************************
 * Name: file_tx_get
 *
 * Description:
 *   Given a file descriptor, return the corresponding instance of struct
 *   file and increment the inode reference conut of this file.
 *   Note: The function based on fs_getfilep, it is can be used to
 *       translate file descriptor between NuttX process
 *
 * Input Parameters:
 *   fd    - The file descriptor
 *   filep - The location to return the struct file instance
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is returned on
 *   any failure.
 *
 ****************************************************************************/

static int file_tx_get(unsigned int fd, FAR struct file *filep)
{
  FAR struct file *file;
  int ret;

  ret = fs_getfilep(fd, &file);
  if (ret < 0)
    {
      return ret;
    }

  ret = file_dup2(file, filep);
  fs_putfilep(file);
  return ret;
}

/****************************************************************************
 * Name: binder_get_object
 *
 * Description:
 *   gets object and checks for valid metadata.
 *   Copy the binder object at the given offset into object. If u is
 *   provided then the copy is from the sender's buffer. If not, then
 *   it is copied from the target's buffer.
 *
 * Input Parameters:
 *   proc   - binder_proc owning the buffer
 *   u      - sender's user pointer to base of buffer
 *   buffer - binder_buffer that we're parsing.
 *   offset - offset in the @buffer at which to validate an object.
 *   object - struct binder_object to read into
 *
 * Returned Value:
 *   If there's a valid metadata object at offset, the
 *   size of that object. Otherwise, it returns zero. The object
 *   is read into the struct binder_object pointed to by object.
 *
 ****************************************************************************/

static size_t binder_get_object(FAR struct binder_proc *proc,
                                FAR const void  *u,
                                FAR struct binder_buffer *buffer,
                                unsigned long offset,
                                FAR struct binder_object *object)
{
  size_t read_size;
  FAR struct binder_object_header *hdr;
  size_t object_size = 0;

  read_size = MIN(sizeof(*object), buffer->data_size - offset);
  if (offset > buffer->data_size || read_size < sizeof(*hdr) ||
      !IS_ALIGNED(offset, sizeof(uint32_t)))
    {
      return 0;
    }

  if (u)
    {
      memcpy(object, u + offset, read_size);
    }
  else
    {
      if (binder_alloc_copy_from_buffer(&proc->alloc, object, buffer, offset,
                                        read_size))
        {
          return 0;
        }
    }

  /* Ok, now see if we read a complete object. */

  hdr = &object->hdr;
  switch (hdr->type)
  {
    case BINDER_TYPE_BINDER:
    case BINDER_TYPE_WEAK_BINDER:
    case BINDER_TYPE_HANDLE:
    case BINDER_TYPE_WEAK_HANDLE:
    {
      object_size = sizeof(struct flat_binder_object);
      break;
    }

    case BINDER_TYPE_FD:
    {
      object_size = sizeof(struct binder_fd_object);
      break;
    }

    case BINDER_TYPE_PTR:
    case BINDER_TYPE_FDA:
    default:
    {
      return 0;
    }
  }

  if (offset <= buffer->data_size - object_size &&
      buffer->data_size >= object_size)
    {
      return object_size;
    }
  else
    {
      return 0;
    }
}

/****************************************************************************
 * Name: binder_get_txn_from
 *
 * Description:
 *   safely extract the "from" thread in transaction.
 *   Atomically return the "from" thread and increment the tmp_ref
 *   count for the thread to ensure it stays alive until
 *   binder_thread_dec_tmpref() is called.
 *
 * Input Parameters:
 *   tran - binder transaction for tran->from
 *
 * Returned Value:
 *   the value of tran->from
 *
 ****************************************************************************/

static struct binder_thread * binder_get_txn_from(
  FAR struct binder_transaction *tran)
{
  FAR struct binder_thread *from;

  nxmutex_lock(&tran->lock);
  from = tran->from;
  if (from)
    {
      binder_inner_proc_lock(from->proc);
      from->tmp_ref++;
      binder_inner_proc_unlock(from->proc);
    }

  nxmutex_unlock(&tran->lock);
  return from;
}

static void binder_pop_transaction_ilocked(
  FAR struct binder_thread *target_thread,
  FAR struct binder_transaction *tran)
{
  BUG_ON(!target_thread);
  binder_inner_proc_assert_locked(target_thread->proc);

  BUG_ON(target_thread->transaction_stack != tran);
  BUG_ON(target_thread->transaction_stack->from != target_thread);

  target_thread->transaction_stack =
    target_thread->transaction_stack->from_parent;
  tran->from = NULL;
}

static void binder_pop_transaction_locked(
  FAR struct binder_proc *proc,
  FAR struct binder_thread *thread,
  FAR struct binder_transaction *tran)
{
  binder_inner_proc_lock(proc);
  binder_pop_transaction_ilocked(thread, tran);
  binder_inner_proc_unlock(proc);
}

/****************************************************************************
 * Name: binder_get_txn_from_and_acq_inner
 *
 * Description:
 *   get tran->from and acquire inner lock
 *
 *   Same as binder_get_txn_from() except it also acquires the
 *   proc->inner_lock to guarantee that the thread cannot be released while
 *   operating on it. The caller must call binder_inner_proc_unlock() to
 *   release the inner lock as well as call binder_dec_thread_txn() to
 *   release the reference.
 *
 * Input Parameters:
 *   tran - binder transaction for tran->from
 *
 * Returned Value:
 *   the value of tran->from
 *
 ****************************************************************************/

static struct binder_thread *binder_get_txn_from_and_acq_inner(
  FAR struct binder_transaction *tran)
{
  FAR struct binder_thread *from;

  from = binder_get_txn_from(tran);
  if (!from)
    {
      return NULL;
    }

  binder_inner_proc_lock(from->proc);
  if (tran->from)
    {
      BUG_ON(from != tran->from);
      return from;
    }

  binder_inner_proc_unlock(from->proc);
  binder_thread_dec_tmpref(from);
  return NULL;
}

/****************************************************************************
 * Name: binder_proc_transaction
 *
 * Description:
 *   sends a transaction to a process and wakes it
 *
 *   This function put to transaction to given process, which will try to
 *   find a thread to handle the transaction and wake it up. If no thread
 *   is found, the work is put to the proccess waitqueue.
 *
 *   If the thread param is not NULL, the transaction is always put to the
 *   waitlist of that given thread.
 *
 * Input Parameters:
 *   tran  - transaction to send
 *   proc   - the transaction target process
 *   thread - thread in proc to send the transaction to (may be NULL)
 *
 * Returned Value:
 *   0: transaction was successfully added
 *   BR_DEAD_REPLY: the target process or thread is dead
 *   BR_FROZEN_REPLY: the target process or thread is frozen
 *
 ****************************************************************************/

static int binder_proc_transaction(FAR struct binder_transaction *tran,
                                   FAR struct binder_proc *proc,
                                   FAR struct binder_thread *thread)
{
  FAR struct binder_node *node = tran->buffer->target_node;
  bool oneway = !!(tran->flags & TF_ONE_WAY);
  bool pending_async = false;

  BUG_ON(!node);
  binder_node_lock(node);

  if (oneway)
    {
      BUG_ON(thread);
      if (node->has_async_trans)
        {
          pending_async = true;
        }
      else
        {
          node->has_async_trans = true;
        }
    }

  binder_inner_proc_lock(proc);
  if (proc->has_frozen)
    {
      proc->sync_recv |= !oneway;
      proc->async_recv |= oneway;
    }

  if ((proc->has_frozen && !oneway) || proc->is_dead ||
      (thread && thread->is_dead))
    {
      binder_inner_proc_unlock(proc);
      binder_node_unlock(node);
      return proc->has_frozen ? BR_FROZEN_REPLY : BR_DEAD_REPLY;
    }

  if (!thread && !pending_async)
    {
      thread = binder_select_thread_ilocked(proc);
    }

  binder_debug(BINDER_DEBUG_TRANSACTION,
               "target %d:%d node %d code %d pending_async: %s oneway: %s\n",
               proc->pid, thread != NULL ? thread->tid : 0, node->id,
               tran->code, pending_async ? "true":"false",
               oneway ? "true":"false");

  if (thread)
    {
      binder_transaction_priority(thread, tran, node);
      binder_enqueue_thread_work_ilocked(thread, &tran->work);
    }
  else if (!pending_async)
    {
      binder_enqueue_work_ilocked(&tran->work, &proc->todo_list);
    }
  else
    {
      binder_enqueue_work_ilocked(&tran->work, &node->async_todo);
    }

  if (!pending_async)
    {
      binder_wakeup_thread_ilocked(proc, thread, !oneway /* sync */);
    }

  proc->outstanding_txns++;
  proc->tmp_ref--;
  binder_inner_proc_unlock(proc);
  binder_node_unlock(node);

  return 0;
}

static int binder_translate_handle(struct flat_binder_object *flat_binder,
                                   struct binder_transaction *tran,
                                   struct binder_thread *thread)
{
  FAR struct binder_proc *proc = thread->proc;
  FAR struct binder_proc *target_proc = tran->to_proc;
  FAR struct binder_node *node_from_ref;
  struct binder_ref_data src_rdata;
  int ret = 0;

  node_from_ref = binder_get_node_from_ref(
                    proc, flat_binder->handle,
                    flat_binder->hdr.type == BINDER_TYPE_HANDLE,
                    &src_rdata);
  if (!node_from_ref)
    {
      return -EINVAL;
    }

  binder_node_lock(node_from_ref);
  if (node_from_ref->proc == target_proc)
    {
      if (flat_binder->hdr.type == BINDER_TYPE_HANDLE)
        {
          flat_binder->hdr.type = BINDER_TYPE_BINDER;
        }
      else
        {
          flat_binder->hdr.type = BINDER_TYPE_WEAK_BINDER;
        }

      flat_binder->binder = node_from_ref->ptr;
      flat_binder->cookie = node_from_ref->cookie;
      if (node_from_ref->proc)
        {
          binder_inner_proc_lock(node_from_ref->proc);
        }

      binder_inc_node_nilocked(node_from_ref,
        flat_binder->hdr.type == BINDER_TYPE_BINDER, 0, NULL);
      if (node_from_ref->proc)
        {
          binder_inner_proc_unlock(node_from_ref->proc);
        }

      binder_node_unlock(node_from_ref);
    }
  else
    {
      struct binder_ref_data dest_rdata;

      binder_node_unlock(node_from_ref);
      ret = binder_inc_ref_for_node(target_proc, node_from_ref,
              flat_binder->hdr.type == BINDER_TYPE_HANDLE,
              NULL, &dest_rdata);
      if (ret)
        {
          goto done;
        }

      flat_binder->binder = 0;
      flat_binder->handle = dest_rdata.desc;
      flat_binder->cookie = 0;
    }

done:
  binder_put_node(node_from_ref);
  return ret;
}

static int binder_translate_binder(FAR struct flat_binder_object *fp,
                                   FAR struct binder_transaction *tran,
                                   FAR struct binder_thread *thread)
{
  FAR struct binder_node *node;
  FAR struct binder_proc *proc = thread->proc;
  FAR struct binder_proc *target_proc = tran->to_proc;
  struct binder_ref_data rdata;
  int ret = 0;

  node = binder_get_node(proc, fp->binder);
  if (!node)
    {
      node = binder_new_node(proc, fp);
      if (!node)
        {
          return -ENOMEM;
        }
    }

  if (fp->cookie != node->cookie)
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "sending %"PRIx64" node %d, cookie mismatch "
                   "%"PRIx64" != %"PRIx64"\n",
                   fp->binder, node->id, fp->cookie,
                   node->cookie);
      ret = -EINVAL;
      goto done;
    }

  ret = binder_inc_ref_for_node(target_proc, node,
                                fp->hdr.type == BINDER_TYPE_BINDER,
                                &thread->todo, &rdata);
  if (ret)
    {
      goto done;
    }

  fp->binder = 0;
  fp->handle = rdata.desc;
  fp->cookie = 0;

  if (fp->hdr.type == BINDER_TYPE_BINDER)
    {
      fp->hdr.type = BINDER_TYPE_HANDLE;
    }
  else
    {
      fp->hdr.type = BINDER_TYPE_WEAK_HANDLE;
    }

done:
  binder_put_node(node);
  return ret;
}

static int binder_translate_fd(uint32_t fd, binder_size_t fd_offset,
                               FAR struct binder_transaction *tran,
                               FAR struct binder_thread *thread,
                               FAR struct binder_transaction *reply_to)
{
  FAR struct binder_txn_fd_fixup *fixup;
  int ret = 0;
  bool target_allows_fd;

  if (reply_to)
    {
      target_allows_fd = !!(reply_to->flags & TF_ACCEPT_FDS);
    }
  else
    {
      target_allows_fd = tran->buffer->target_node->accept_fds;
    }

  if (!target_allows_fd)
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "got %s with fd, %"PRId32", "
                   "but target does not allow fds\n",
                   reply_to ? "reply" : "transaction", fd);
      ret = -EPERM;
      goto err_fd_not_accepted;
    }

  /* Add fixup record for this transaction. The allocation
   * of the fd in the target needs to be done from a
   * target thread.
   */

  fixup = kmm_zalloc(sizeof(*fixup));
  if (!fixup)
    {
      ret = -ENOMEM;
      goto err_alloc;
    }

  list_initialize(&fixup->fixup_entry);
  ret = file_tx_get(fd, &fixup->file);
  if (ret < 0)
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "got transaction with invalid fd, %" PRId32 "\n", fd);
      ret = -EBADF;
      goto err_fget;
    }

  fixup->offset = fd_offset;
  list_add_tail(&fixup->fixup_entry, &tran->fd_fixups);

  return ret;

err_fget:
  kmm_free(fixup);
err_alloc:
err_fd_not_accepted:
  return ret;
}

/****************************************************************************
 * Name: binder_get_node_refs_for_txn
 *
 * Description:
 *   Get required refs on node for txn.
 *
 *   User-space normally keeps the node alive when creating a transaction
 *   since it has a reference to the target. The local strong ref keeps it
 *   alive if the sending process dies before the target process processes
 *   the transaction. If the source process is malicious or has a reference
 *   counting bug, relying on the local strong ref can fail.
 *
 *   Since user-space can cause the local strong ref to go away, we also take
 *   a tmpref on the node to ensure it survives while we are constructing
 *   the transaction. We also need a tmpref on the proc while we are
 *   constructing the transaction, so we take that here as well.
 *
 * Input Parameters:
 *   node  - struct binder_node for which to get refs
 *   proc  - returns node->proc if valid
 *   error - if no proc then returns BR_DEAD_REPLY
 *
 * Returned Value:
 *   The target_node with refs taken or NULL if no node->proc is NULL.
 *   Also sets proc if valid. If the node->proc is NULL indicating that the
 *   target proc has died, error is set to BR_DEAD_REPLY
 *
 ****************************************************************************/

static struct binder_node *binder_get_node_refs_for_txn(
  FAR struct binder_node *node, FAR struct binder_proc **procp,
  FAR int *error)
{
  FAR struct binder_node *target_node = NULL;

  binder_node_inner_lock(node);
  if (node->proc)
    {
      target_node = node;
      binder_inc_node_nilocked(node, 1, 0, NULL);
      binder_inc_node_tmpref_ilocked(node);
      node->proc->tmp_ref++;
      *procp = node->proc;
    }
  else
    {
      *error = BR_DEAD_REPLY;
    }

  binder_node_inner_unlock(node);

  return target_node;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void binder_transaction_buffer_release(FAR struct binder_proc *proc,
                                       FAR struct binder_thread *thread,
                                       FAR struct binder_buffer *buffer,
                                       binder_size_t off_end_offset,
                                       bool is_failure)
{
  binder_size_t off_start_offset, buffer_offset;

  binder_debug(BINDER_DEBUG_TRANSACTION,
               "buffer release %d, size %d-%d, failed at %" PRIx64 "\n",
               buffer->id, buffer->data_size, buffer->offsets_size,
               off_end_offset);

  if (buffer->target_node)
    {
      binder_dec_node(buffer->target_node, 1, 0);
    }

  off_start_offset = ALIGN(buffer->data_size, sizeof(void *));

  for (buffer_offset = off_start_offset;
       buffer_offset < off_end_offset;
       buffer_offset += sizeof(binder_size_t))
    {
      struct binder_object_header *hdr;
      size_t object_size = 0;
      struct binder_object object;
      binder_size_t object_offset;

      if (!binder_alloc_copy_from_buffer(
               &proc->alloc, &object_offset, buffer,
               buffer_offset, sizeof(object_offset)))
        {
          object_size = binder_get_object(proc, NULL, buffer,
                                         object_offset, &object);
        }

      if (object_size == 0)
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "transaction release %d bad object at "
                       "offset %" PRId64 ", size %d\n",
                       buffer->id, object_offset,
                       buffer->data_size);
          continue;
        }

      hdr = &object.hdr;
      switch (hdr->type)
      {
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE:
        {
          FAR struct flat_binder_object *flat_binder;
          struct binder_ref_data ref_data;
          int ret;

          flat_binder = to_flat_binder_object(hdr);
          ret = binder_dec_ref_for_handle(proc, flat_binder->handle,
                                            hdr->type == BINDER_TYPE_HANDLE,
                                            &ref_data);
          if (ret)
            {
              binder_debug(BINDER_DEBUG_ERROR,
                           "transaction release %d "
                           "bad handle %" PRIu32 ", ret = %d\n",
                           ref_data.id, flat_binder->handle, ret);
              break;
            }

          binder_debug(BINDER_DEBUG_TRANSACTION, "ref %d desc %" PRIu32 "\n",
                       ref_data.id, ref_data.desc);
          break;
        }

        case BINDER_TYPE_FD:
        {
          break;
        }

        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER:
        {
          FAR struct flat_binder_object *flat_binder =
                       to_flat_binder_object(hdr);
          FAR struct binder_node *get_node =
                       binder_get_node(proc, flat_binder->binder);

          if (get_node == NULL)
            {
              binder_debug(BINDER_DEBUG_ERROR,
                           "transaction release %d bad node %"PRIx64"\n",
                           get_node->id, flat_binder->binder);
              break;
            }

          binder_debug(BINDER_DEBUG_TRANSACTION, "node %d %" PRIx64 "\n",
                       get_node->id, get_node->ptr);
          binder_dec_node(get_node, hdr->type == BINDER_TYPE_BINDER, 0);
          binder_put_node(get_node);
          break;
        }

        case BINDER_TYPE_PTR:
        case BINDER_TYPE_FDA:
        default:
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "transaction release %d bad object type %d\n",
                       buffer->id, (int)hdr->type);
          break;
        }
      }
    }
}

/****************************************************************************
 * Name: binder_release_entire_buffer
 *
 * Description:
 *   Clean up all the objects in the buffer
 *
 ****************************************************************************/

void binder_release_entire_buffer(FAR struct binder_proc *proc,
                                  FAR struct binder_thread *thread,
                                  FAR struct binder_buffer *buffer,
                                  bool is_failure)
{
  binder_size_t off_end_offset;

  off_end_offset = ALIGN(buffer->data_size, sizeof(void *));
  off_end_offset += buffer->offsets_size;

  binder_transaction_buffer_release(proc, thread, buffer,
                                    off_end_offset, is_failure);
}

/****************************************************************************
 * Name: binder_deferred_fd_close
 *
 * Description:
 *   schedule a close for the given file-descriptor
 *
 * Input Parameters:
 *   fd - file-descriptor to close
 *
 ****************************************************************************/

void binder_deferred_fd_close(int fd)
{
  int ret;

  ret = nx_close(fd);
  if (ret < 0)
    {
      binder_debug(BINDER_DEBUG_ERROR, "errno nx_close, ret =%d\n", ret);
    }
}

void binder_transaction_priority(FAR struct binder_thread *thread,
                                 FAR struct binder_transaction *tran,
                                 FAR struct binder_node *node)
{
  struct binder_priority desired =
  {
    .sched_policy = tran->priority.sched_policy,
    .sched_prio = tran->priority.sched_prio,
  };

  const struct binder_priority node_prio =
  {
    .sched_policy = node->sched_policy,
    .sched_prio = node->min_priority,
  };

  if (tran->set_priority_called)
    {
      return;
    }

  tran->set_priority_called = true;

  binder_get_priority(thread->tid, &tran->saved_priority);

  if (node_prio.sched_prio > desired.sched_prio)
    {
      binder_set_priority(thread, &node_prio);
    }
  else
    {
      binder_set_priority(thread, &desired);
    }
}

void binder_send_failed_reply(FAR struct binder_transaction *tran,
                              uint32_t error_code)
{
  FAR struct binder_thread *target;
  FAR struct binder_transaction *next_tran;

  BUG_ON(tran->flags & TF_ONE_WAY);
  while (1)
    {
      target = binder_get_txn_from_and_acq_inner(tran);
      if (target)
        {
          binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
                       "send reply failed %d to %d:%d\n",
                       tran->id, target->proc->pid,
                       target->tid);

          binder_pop_transaction_ilocked(target, tran);
          if (target->reply_error.cmd == BR_OK)
            {
              target->reply_error.cmd = error_code;
              binder_enqueue_thread_work_ilocked(
                  target, &target->reply_error.work);
              wait_wake_up(&target->wait, 0);
            }
          else
            {
              binder_debug(BINDER_DEBUG_WARNING,
                           "reply error: %" PRIu32 "\n",
                           target->reply_error.cmd);
            }

          binder_inner_proc_unlock(target->proc);
          binder_thread_dec_tmpref(target);
          binder_free_transaction(tran);
          return;
        }

      next_tran = tran->from_parent;

      binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
                   "send reply failed %d, target dead\n",
                   tran->id);

      binder_free_transaction(tran);
      if (!next_tran)
        {
          binder_debug(BINDER_DEBUG_DEAD_BINDER,
                       "reply failed, no target thread\n");
          return;
        }

      tran = next_tran;
      binder_debug(BINDER_DEBUG_DEAD_BINDER,
                   "reply failed, no target thread -- retry %d\n",
                   tran->id);
    }
}

/****************************************************************************
 * Name: binder_cleanup_transaction
 *
 * Description:
 *   cleans up undelivered transaction
 *
 * Input Parameters:
 *   tran       - transaction that needs to be cleaned up
 *   reason     - reason the transaction wasn'tran delivered
 *   error_code - error to return to caller (if synchronous call)
 *
 ****************************************************************************/

void binder_cleanup_transaction(FAR struct binder_transaction *tran,
                                FAR const char *reason, uint32_t error_code)
{
  if (tran->buffer->target_node && !(tran->flags & TF_ONE_WAY))
    {
      binder_send_failed_reply(tran, error_code);
    }
  else
    {
      binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
                   "undelivered transaction %d, %s\n", tran->id, reason);
      binder_free_transaction(tran);
    }
}

void binder_free_transaction(FAR struct binder_transaction *tran)
{
  FAR struct binder_proc *target_proc = tran->to_proc;

  if (target_proc)
    {
      binder_inner_proc_lock(target_proc);
      target_proc->outstanding_txns--;
      if (target_proc->outstanding_txns < 0)
        {
          binder_debug(BINDER_DEBUG_WARNING,
                       "Unexpected outstanding_txns %d\n",
                       target_proc->outstanding_txns);
        }

      if (!target_proc->outstanding_txns && target_proc->has_frozen)
        {
          wait_wake_up(&target_proc->freeze_wait, 0);
        }

      if (tran->buffer)
        {
          tran->buffer->transaction = NULL;
        }

      binder_inner_proc_unlock(target_proc);
    }

  kmm_free(tran);
}

static void binder_prepare_transaction(FAR struct binder_proc *proc,
                               FAR struct binder_transaction *tran,
                               FAR struct binder_thread *thread,
                               FAR struct binder_work *complete_work)
{
  binder_inner_proc_lock(proc);
  binder_enqueue_deferred_thread_work_ilocked(thread, complete_work);
  tran->need_reply = 1;
  tran->from_parent = thread->transaction_stack;
  thread->transaction_stack = tran;
  binder_inner_proc_unlock(proc);
}

static void binder_waiting_transaction(FAR struct binder_transaction *tran,
                                FAR struct binder_thread *thread,
                                FAR struct binder_thread *target_thread,
                                FAR struct binder_proc *target_proc,
                                FAR struct binder_transaction *reply_to)
{
  BUG_ON(tran->buffer->async_transaction != 0);
  binder_pop_transaction_ilocked(target_thread, reply_to);
  binder_enqueue_thread_work_ilocked(target_thread, &tran->work);
  target_proc->outstanding_txns++;
  target_proc->tmp_ref--;
  binder_inner_proc_unlock(target_proc);
  wait_wake_up(&target_thread->wait, 0);
  binder_set_priority(thread, &reply_to->saved_priority);
  binder_free_transaction(reply_to);
}

void binder_transaction(FAR struct binder_proc *proc,
                        FAR struct binder_thread *thread,
                        FAR struct binder_transaction_data *trans, int reply)
{
  binder_size_t buffer_offset = 0;
  binder_size_t min_offset;
  binder_size_t user_offset = 0;
  FAR struct binder_transaction *tran;
  FAR struct binder_work *w;
  FAR struct binder_work *complete_work;
  FAR struct binder_proc *target_proc = NULL;
  FAR struct binder_thread *target_thread = NULL;
  FAR struct binder_node *target_node = NULL;
  FAR struct binder_transaction *reply_to = NULL;
  FAR struct binder_context *context = proc->context;
  FAR const void *user_buffer =
      (const void *)(uintptr_t)trans->data.ptr.buffer;
  int ret = 0;
  int return_error = 0;

  if (reply)
    {
      binder_inner_proc_lock(proc);
      reply_to = thread->transaction_stack;
      if (!reply_to)
        {
          binder_inner_proc_unlock(proc);
          return_error = BR_FAILED_REPLY;
          goto err_empty_call_stack;
        }

      if (reply_to->to_thread != thread)
        {
          binder_inner_proc_unlock(proc);
          return_error = BR_FAILED_REPLY;
          reply_to = NULL;
          goto err_bad_call_stack;
        }

      thread->transaction_stack = reply_to->to_parent;
      binder_inner_proc_unlock(proc);
      target_thread = binder_get_txn_from_and_acq_inner(reply_to);
      if (!target_thread)
        {
          return_error = BR_DEAD_REPLY;
          goto err_dead_binder;
        }

      if (target_thread->transaction_stack != reply_to)
        {
          binder_debug(BINDER_DEBUG_ERROR, "target bad transaction stack\n");
          BUG_ON(!nxmutex_is_hold(&target_thread->proc->inner_lock));
          binder_inner_proc_unlock(target_thread->proc);
          return_error = BR_FAILED_REPLY;
          reply_to = NULL;
          target_thread = NULL;
          goto err_dead_binder;
        }

      target_proc = target_thread->proc;
      target_proc->tmp_ref++;
      BUG_ON(!nxmutex_is_hold(&target_thread->proc->inner_lock));

      binder_inner_proc_unlock(target_thread->proc);
    }
  else
    {
      if (trans->target.handle)
        {
          struct binder_ref *ref;
          binder_proc_lock(proc);
          ref = binder_get_ref_olocked(proc, trans->target.handle, true);
          if (ref)
            {
              target_node = binder_get_node_refs_for_txn(
                 ref->node, &target_proc, &return_error);
            }
          else
            {
              binder_debug(BINDER_DEBUG_ERROR, "invalid handle\n");
              return_error = BR_FAILED_REPLY;
            }

          binder_proc_unlock(proc);
        }
      else
        {
          nxmutex_lock(&context->context_lock);
          target_node = context->mgr_node;
          if (target_node)
            {
              target_node = binder_get_node_refs_for_txn(
                  target_node, &target_proc, &return_error);
            }
          else
            {
              return_error = BR_DEAD_REPLY;
            }

          nxmutex_unlock(&context->context_lock);
          if (target_node && target_proc->pid == proc->pid)
            {
              binder_debug(BINDER_DEBUG_ERROR,
                           "[%s][%d:%d]:"
                           "got transaction to context manager "
                           "from process owning it\n",
                           LOG_TAG, getpid(), gettid());
              return_error = BR_FAILED_REPLY;
              goto err_invalid_target_handle;
            }
        }

      if (!target_node)
        {
          /* return_error is set above */

          goto err_dead_binder;
        }

      if (proc == target_proc)
        {
          WARN_ON(1);
          return_error = BR_FAILED_REPLY;
          goto err_invalid_target_handle;
        }

      binder_inner_proc_lock(proc);
      w = list_first_entry_or_null(&thread->todo, struct binder_work,
                                   entry_node);
      if (!(trans->flags & TF_ONE_WAY) && w &&
          w->type == BINDER_WORK_TRANSACTION)
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "[%s][%d:%d]:"
                       "new transaction not allowed when there is "
                       "a transaction on thread todo\n",
                       LOG_TAG, getpid(), gettid());
          binder_inner_proc_unlock(proc);
          return_error = BR_FAILED_REPLY;
          goto err_bad_todo_list;
        }

      if (!(trans->flags & TF_ONE_WAY) && thread->transaction_stack)
        {
          FAR struct binder_transaction *tmp;
          tmp = thread->transaction_stack;
          if (tmp->to_thread != thread)
            {
              nxmutex_lock(&tmp->lock);
              binder_debug(BINDER_DEBUG_ERROR,
                           "got new transaction with bad transaction "
                           "stack, transaction %d has target %d:%d\n",
                           tmp->id,
                           tmp->to_proc ? tmp->to_proc->pid : 0,
                           tmp->to_thread ? tmp->to_thread->tid : 0);
              nxmutex_unlock(&tmp->lock);
              binder_inner_proc_unlock(proc);
              return_error = BR_FAILED_REPLY;
              goto err_bad_call_stack;
            }

          while (tmp)
            {
              FAR struct binder_thread *from;
              nxmutex_lock(&tmp->lock);
              from = tmp->from;
              if (from && from->proc == target_proc)
                {
                  from->tmp_ref++;
                  target_thread = from;
                  nxmutex_unlock(&tmp->lock);
                  break;
                }

              nxmutex_unlock(&tmp->lock);
              tmp = tmp->from_parent;
            }
        }

      binder_inner_proc_unlock(proc);
    }

  /* TODO: reuse incoming transaction for reply */

  tran = kmm_zalloc(sizeof(struct binder_transaction));
  if (tran == NULL)
    {
      return_error = BR_FAILED_REPLY;
      goto err_alloc_t_failed;
    }

  list_initialize(&tran->fd_fixups);
  list_initialize(&tran->work.entry_node);
  nxmutex_init(&tran->lock);
  complete_work = kmm_zalloc(sizeof(struct binder_work));
  if (complete_work == NULL)
    {
      return_error = BR_FAILED_REPLY;
      goto err_alloc_tcomplete_failed;
    }

  list_initialize(&complete_work->entry_node);

  if (reply)
    {
      binder_debug(BINDER_DEBUG_TRANSACTION,
                   "%d:%d BC_REPLY -> %d:%d, data %"PRIx64"-%"PRIx64" "
                   "size %"PRId64"-%"PRId64"\n",
                   proc->pid, thread->tid, target_proc->pid,
                   target_thread->tid, trans->data.ptr.buffer,
                   trans->data.ptr.offsets, trans->data_size,
                   trans->offsets_size);
    }
  else
    {
      binder_debug(BINDER_DEBUG_TRANSACTION,
                   "%d:%d BC_TRANSACTION -> %d-node %d, "
                   "data %"PRIx64"-%"PRIx64" "
                   "size %"PRId64"-%"PRId64"\n",
                   proc->pid, thread->tid, target_proc->pid,
                   target_node->id, trans->data.ptr.buffer,
                   trans->data.ptr.offsets, trans->data_size,
                   trans->offsets_size);
    }

  if (!reply && !(trans->flags & TF_ONE_WAY))
    {
      tran->from = thread;
    }
  else
    {
      tran->from = NULL;
    }

  tran->sender_euid = geteuid_bypid(proc->pid);
  tran->to_proc = target_proc;
  tran->to_thread = target_thread;
  tran->code = trans->code;
  tran->flags = trans->flags;

  if (!(tran->flags & TF_ONE_WAY) && binder_supported_policy(gettid()))
    {
      binder_get_priority(gettid(), &tran->priority);
    }
  else
    {
      /* Otherwise, fall back to the default priority */

      tran->priority.sched_prio =
        target_proc->default_priority.sched_prio;
      tran->priority.sched_policy =
        target_proc->default_priority.sched_policy;
    }

  tran->buffer =
    binder_alloc_new_buf(&target_proc->alloc, trans->data_size,
                         trans->offsets_size, 0,
                         !reply && (tran->flags & TF_ONE_WAY),
                         &ret);
  if (ret < 0)
    {
      /* -ESRCH indicates VMA cleared. The target is dying. */

      return_error = ret ==
                     -ESRCH ?BR_DEAD_REPLY : BR_FAILED_REPLY;
      tran->buffer = NULL;
      goto err_binder_alloc_buf_failed;
    }

  tran->buffer->id = tran->id;
  tran->buffer->transaction = tran;
  tran->buffer->target_node = target_node;
  tran->buffer->clear_on_free = !!(tran->flags & TF_CLEAR_BUF);

  if (binder_alloc_copy_to_buffer(&target_proc->alloc, tran->buffer,
                      ALIGN(trans->data_size, sizeof(void *)),
                      (FAR void *)(uintptr_t)trans->data.ptr.offsets,
                      trans->offsets_size))
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "[%s][%d:%d]:"
                   "got transaction with invalid offsets ptr\n",
                   LOG_TAG, getpid(), gettid());
      return_error = BR_FAILED_REPLY;
      goto err_copy_data_failed;
    }

  if (!IS_ALIGNED(trans->offsets_size, sizeof(binder_size_t)))
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "got transaction with invalid offsets size, "
                   "%"PRId64"\n", trans->offsets_size);
      return_error = BR_FAILED_REPLY;
      goto err_bad_offset;
    }

  min_offset = 0;
  for (buffer_offset = ALIGN(trans->data_size, sizeof(void *));
       buffer_offset <
       ALIGN(trans->data_size, sizeof(void *)) + trans->offsets_size;
       buffer_offset += sizeof(binder_size_t))
    {
      FAR struct binder_object_header *hdr;
      size_t object_size;
      struct binder_object object;
      binder_size_t object_offset;
      binder_size_t copy_size;

      if (binder_alloc_copy_from_buffer(&target_proc->alloc, &object_offset,
                                        tran->buffer, buffer_offset,
                                        sizeof(object_offset)))
        {
          return_error = BR_FAILED_REPLY;
          goto err_bad_offset;
        }

      copy_size = object_offset - user_offset;
      if (copy_size &&
          (user_offset > object_offset ||
           binder_alloc_copy_to_buffer(&target_proc->alloc, tran->buffer,
                                       user_offset,
                                       (void *)(user_buffer + user_offset),
                                       copy_size)))
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "[%s][%d:%d]:"
                       "got transaction with invalid data ptr\n",
                       LOG_TAG, getpid(), gettid());
          return_error = BR_FAILED_REPLY;
          goto err_copy_data_failed;
        }

      object_size = binder_get_object(target_proc, user_buffer,
                                      tran->buffer,
                                      object_offset, &object);
      if (object_size == 0 || object_offset < min_offset)
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "got transaction with invalid offset "
                       "(%"PRId64", min %"PRId64" max %d) or object.\n",
                       object_offset, min_offset, tran->buffer->data_size);
          return_error = BR_FAILED_REPLY;
          goto err_bad_offset;
        }

      user_offset = object_offset + object_size;
      hdr = &object.hdr;
      min_offset = object_offset + object_size;
      switch (hdr->type)
      {
        case BINDER_TYPE_WEAK_HANDLE:
        case BINDER_TYPE_HANDLE:
        {
          FAR struct flat_binder_object *fp;
          fp = to_flat_binder_object(hdr);
          ret = binder_translate_handle(fp, tran, thread);
          if (ret < 0 ||
              binder_alloc_copy_to_buffer(&target_proc->alloc, tran->buffer,
                                          object_offset, fp, sizeof(*fp)))
            {
              return_error = BR_FAILED_REPLY;
              goto err_translate_failed;
            }

          break;
        }

        case BINDER_TYPE_FD:
        {
          FAR struct binder_fd_object *fp = to_binder_fd_object(hdr);
          binder_size_t offset = object_offset +
                                                  (uintptr_t)&fp->fd -
                                                  (uintptr_t)fp;
          int ret_local = binder_translate_fd(fp->fd,
                                              offset,
                                              tran, thread,
                                              reply_to);
          fp->pad_binder = 0;
          if (ret_local < 0 ||
              binder_alloc_copy_to_buffer(&target_proc->alloc, tran->buffer,
                                          object_offset, fp, sizeof(*fp)))
            {
              return_error = BR_FAILED_REPLY;
              goto err_translate_failed;
            }
          break;
        }

        case BINDER_TYPE_WEAK_BINDER:
        case BINDER_TYPE_BINDER:
        {
          FAR struct flat_binder_object *fp;
          fp = to_flat_binder_object(hdr);
          ret = binder_translate_binder(fp, tran, thread);
          if (ret < 0 ||
              binder_alloc_copy_to_buffer(&target_proc->alloc, tran->buffer,
                                          object_offset, fp, sizeof(*fp)))
            {
              return_error = BR_FAILED_REPLY;
              goto err_translate_failed;
            }
          break;
        }

        case BINDER_TYPE_FDA:
        case BINDER_TYPE_PTR:
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "BINDER_TYPE_FDA or BINDER_TYPE_PTR "
                       "Unsupport for NuttX, "
                       "%" PRIx32 "\n", hdr->type);
          BUG_ON(1);
          break;
        }

        default:
        {
          binder_debug(BINDER_DEBUG_ERROR,
                       "got transaction with invalid object type, "
                       "%" PRIx32 "\n", hdr->type);
          return_error = BR_FAILED_REPLY;
          goto err_bad_object_type;
        }
      }
    }

  /* Done processing objects, copy the rest of the buffer */

  if (binder_alloc_copy_to_buffer(&target_proc->alloc,
              tran->buffer, user_offset,
              (void *)(user_buffer + user_offset),
              trans->data_size - user_offset))
    {
      binder_debug(BINDER_DEBUG_ERROR,
                   "[%s][%d:%d]:"
                   "got transaction with invalid data ptr\n",
                   LOG_TAG, getpid(), gettid());
      return_error = BR_FAILED_REPLY;
      goto err_copy_data_failed;
    }

  complete_work->type = BINDER_WORK_TRANSACTION_COMPLETE;
  tran->work.type = BINDER_WORK_TRANSACTION;
  if (reply)
    {
      binder_enqueue_thread_work(thread, complete_work);
      binder_inner_proc_lock(target_proc);
      if (target_thread->is_dead)
        {
          return_error = BR_DEAD_REPLY;
          binder_inner_proc_unlock(target_proc);
          goto err_dead;
        }

      binder_waiting_transaction(tran, thread, target_thread,
                                  target_proc, reply_to);
    }
  else if (!(tran->flags & TF_ONE_WAY))
    {
      BUG_ON(tran->buffer->async_transaction != 0);
      binder_prepare_transaction(proc, tran, thread, complete_work);
      return_error = binder_proc_transaction(
        tran, target_proc, target_thread);
      if (return_error)
        {
          binder_pop_transaction_locked(proc, thread, tran);
          goto err_dead;
        }
    }
  else
    {
      BUG_ON(target_node == NULL && tran->buffer->async_transaction != 1);
      binder_enqueue_thread_work(thread, complete_work);
      return_error = binder_proc_transaction(tran, target_proc, NULL);
      if (return_error)
        {
          goto err_dead;
        }
    }

  if (target_thread)
    {
      binder_thread_dec_tmpref(target_thread);
    }

  if (target_node)
    {
      binder_dec_node_tmpref(target_node);
    }

  return;

err_dead:
  binder_dequeue_work(proc, complete_work);
err_translate_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
  binder_transaction_buffer_release(target_proc, NULL, tran->buffer,
                                    buffer_offset, true);
  if (target_node)
    {
      binder_dec_node_tmpref(target_node);
    }

  target_node = NULL;
  tran->buffer->transaction = NULL;
  binder_alloc_free_buf(&target_proc->alloc, tran->buffer);
err_binder_alloc_buf_failed:
  kmm_free(complete_work);
err_alloc_tcomplete_failed:
  kmm_free(tran);
err_alloc_t_failed:
err_bad_todo_list:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
  if (target_node)
    {
      binder_dec_node(target_node, 1, 0);
      binder_dec_node_tmpref(target_node);
    }

  if (target_thread)
    {
      binder_thread_dec_tmpref(target_thread);
    }

  if (target_proc)
    {
      binder_proc_dec_tmpref(target_proc);
    }

  binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
               "%d:%d transaction %s to %d:%d failed %d,"
               "size %"PRId64"-%"PRId64"\n",
               proc->pid, thread->tid, reply ? "reply" :
               (trans->flags & TF_ONE_WAY ? "async" : "call"),
               target_proc ? target_proc->pid : 0,
               target_thread ? target_thread->tid : 0,
               return_error, trans->data_size, trans->offsets_size);

  if (return_error != BR_FROZEN_REPLY)
    {
      binder_debug(BINDER_DEBUG_WARNING,
                   "[%s][%d:%d]:" "transaction failed %d, "
                   "size %"PRId64"-%"PRId64"\n",
                   LOG_TAG, getpid(), gettid(),
                   return_error, trans->data_size, trans->offsets_size);
    }

  BUG_ON(thread->return_error.cmd != BR_OK);
  if (reply_to)
    {
      binder_set_priority(thread, &reply_to->saved_priority);
      thread->return_error.cmd = BR_TRANSACTION_COMPLETE;
      binder_enqueue_thread_work(thread, &thread->return_error.work);
      binder_send_failed_reply(reply_to, return_error);
    }
  else
    {
      thread->return_error.cmd = return_error;
      binder_enqueue_thread_work(thread, &thread->return_error.work);
    }
}
