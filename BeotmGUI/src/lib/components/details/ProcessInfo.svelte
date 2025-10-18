<script lang="ts">
  import { t } from 'svelte-i18n';
  import CopyText from '../CopyText.svelte';

  const {
    name,
    pid,
    path,
  }: {
    name: string;
    pid: number;
    path?: string;
  } = $props();
</script>

<div class="grid w-full grid-cols-[5rem_20rem] items-center gap-x-4 text-xs">
  <div class="text-right">{$t('event_details.name')}</div>
  <div class="min-w-0 text-xl font-bold"><CopyText text={name}></CopyText></div>

  <div class="text-right">{$t('event_details.pid')}</div>
  <div class="min-w-0 text-xl font-bold"><CopyText text={pid.toString()}></CopyText></div>

  {#if path}
    <div class="text-right">{$t('event_details.image_path')}</div>
    <div class="flex min-w-0 font-bold whitespace-normal">
      {@html path.replace(/\\/g, '\\<wbr>')}
      <CopyText text={path} showText={false}></CopyText>
    </div>
  {/if}
</div>
