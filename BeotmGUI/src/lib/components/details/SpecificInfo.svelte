<script lang="ts">
  import { t } from 'svelte-i18n';
  import type { DetectionEvent, SpecificEventsInfo } from '$lib/schemas/detection-events';
  import SpecificInfoViewer from './SpecificInfoViewer.svelte';
  let { selected }: { selected: DetectionEvent } = $props();

  const getSpecificInfoKey = (info: SpecificEventsInfo) => Object.keys(info)[0];

  const getSpecificInfoAssociation = (info: SpecificEventsInfo) =>
    Object.entries((info as any)[getSpecificInfoKey(info)]).map(([key, value]) => [key, value]);
</script>

<div class="p-2">
  <div class="text-sm">
    {$t('event_details.specific_info')}
  </div>
  {#each selected.SpecificEventsInfo as info}
    <div>
      <div class="pt-2 text-xl font-bold">{getSpecificInfoKey(info)}</div>
      <div class="border-t-[0.5px] border-r-[0.5px]">
        <SpecificInfoViewer data={getSpecificInfoAssociation(info)}></SpecificInfoViewer>
      </div>
    </div>
  {/each}
</div>
