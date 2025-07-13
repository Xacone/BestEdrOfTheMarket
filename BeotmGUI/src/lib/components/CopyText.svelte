<script lang="ts">
  import type { AppNotification } from '$lib/schemas/notification';
  import ClipboardCopy from '@lucide/svelte/icons/clipboard-copy';
  import { t } from 'svelte-i18n';
  let { text, notification = $bindable() }: { text: string; notification: AppNotification | null } =
    $props();

  async function copyText() {
    notification = {
      message: 'Text successfully copied to clipboard',
      level: 'success',
      remove: false,
    };
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      notification = {
        message: $t('event_details.error_copy_path'),
        level: 'error',
        remove: false,
      };
    }
  }
</script>

{text}
<button
  id="close-panel"
  onclick={() => copyText()}
  class="cursor-pointer"
  title={$t('event_details.tooltip.copy_path')}
>
  <ClipboardCopy class="h-4 w-4" strokeWidth="0.7" />
</button>
