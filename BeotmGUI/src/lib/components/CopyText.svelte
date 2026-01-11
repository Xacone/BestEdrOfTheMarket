<script lang="ts">
  import { getToast } from '$lib/logic/toast.svelte';
  import ClipboardCopy from '@lucide/svelte/icons/clipboard-copy';
  import { t } from 'svelte-i18n';
  let { text, showText = true }: { text: string; showText?: boolean } = $props();

  const toast = getToast();

  async function copyText() {
    try {
      await navigator.clipboard.writeText(text);
      toast.trigger({
        message: 'Text successfully copied to clipboard',
        level: 'success',
      });
    } catch (err) {
      console.error(err);
      toast.trigger({
        message: $t('event_details.error_copy_path'),
        level: 'error',
      });
    }
  }
</script>

{#if showText}
  {text}
{/if}
<button
  class="btn btn-ghost btn-square btn-xs"
  onclick={copyText}
  title={$t('event_details.tooltip.copy_path')}
>
  <ClipboardCopy class="h-4 w-4" strokeWidth="0.7" />
</button>
