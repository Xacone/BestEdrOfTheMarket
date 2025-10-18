<script lang="ts">
  import { getToast } from '$lib/logic/toast.svelte';
  import { LevelAlert } from '$lib/schemas/graphical-event';
  import CircleX from '@lucide/svelte/icons/circle-x';

  const toast = getToast();
</script>

<div class="toast toast-top toast-center">
  {#each toast.notifications as notification}
    <div class="alert {LevelAlert[notification.level]}" role="alert">
      <span>
        {notification.message}
      </span>
      <button class="btn btn-circle btn-xs btn-ghost" aria-label="close">
        <CircleX strokeWidth="0.7" onclick={() => toast.remove(notification.id)}></CircleX>
      </button>
    </div>
  {/each}
</div>
