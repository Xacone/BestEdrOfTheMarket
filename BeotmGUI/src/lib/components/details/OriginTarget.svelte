<script lang="ts">
  import { t } from 'svelte-i18n';
  import ProcessInfo from './ProcessInfo.svelte';
  import type { DetectionEvent } from '$lib/schemas/detection-events';
  let { selected }: { selected: DetectionEvent } = $props();
</script>

<div class="flex w-full flex-wrap gap-5 p-2">
  <div class="flex flex-1 grow flex-col">
    <div class="flex items-center justify-start gap-1 p-1 text-sm">
      {$t('event_details.origin_process')}
    </div>
    <ProcessInfo
      name={selected.OriginProcess}
      pid={selected.OriginPID}
      path={selected.OriginProcessImagePath}
    ></ProcessInfo>
  </div>
  <div class="flex flex-1 grow flex-col">
    <div class="flex items-center justify-start gap-1 p-1 text-sm">
      {$t('event_details.target_process')}
    </div>
    <ProcessInfo name={selected.VictimProcess} pid={selected.TargetPID}></ProcessInfo>
  </div>
</div>
