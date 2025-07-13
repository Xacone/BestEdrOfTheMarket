<script lang="ts">
  import type { AppNotification } from '$lib/schemas/notification';
  import CircleX from '@lucide/svelte/icons/circle-x';
  import { onDestroy } from 'svelte';

  let { notification = $bindable() }: { notification: AppNotification } = $props();
  const alertClass = `alert-${notification.level}`;

  const timeoutID = setTimeout(() => {
    notification.remove = true;
  }, 3000);

  onDestroy(() => {
    clearTimeout(timeoutID);
  });
</script>

<!-- Why not a modal to list all the notifications -->
<!-- https://daisyui.com/components/modal/ -->
<div class="toast toast-top toast-center">
  <div class="alert {alertClass}" role="alert">
    <span>
      {notification.message}
    </span>
    <button aria-label="close">
      <CircleX
        strokeWidth="0.7"
        onclick={() => {
          notification.remove = true;
        }}
      ></CircleX>
    </button>
  </div>
</div>
