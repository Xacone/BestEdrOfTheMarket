<script lang="ts">
  import Scale from '@lucide/svelte/icons/scale';
  import SquareFunction from '@lucide/svelte/icons/square-function';
  import Syringe from '@lucide/svelte/icons/syringe';
  import CopyText from '../CopyText.svelte';
  import { t } from 'svelte-i18n';
  import type { DetectionEvent } from '$lib/schemas/detection-events';

  let { selected }: { selected: DetectionEvent } = $props();
</script>

<div class="flex flex-col gap-2 p-2">
  <div class="flex flex-col">
    <div class="flex items-center gap-1 text-sm">
      <SquareFunction class="h-4 w-4" strokeWidth="0.7"></SquareFunction>{$t(
        'event_details.defensive_method',
      )}
    </div>
    <div class="text-xl font-bold">
      <CopyText text={selected.GlobalDefensiveMethod}></CopyText>
    </div>
  </div>
  <div class="flex flex-col">
    <div class="flex items-center gap-1 text-sm">
      <Scale strokeWidth="0.7" class="h-4 w-4"></Scale>{$t('event_details.yara_rule')}
    </div>
    <div class="text-xl font-bold">
      <CopyText text={selected.InvolvedYaraRule}></CopyText>
    </div>
  </div>
  <div class="flex flex-col">
    <div class="flex items-center gap-1 text-sm">
      <Syringe strokeWidth="0.7" class="h-4 w-4"></Syringe>{$t('event_details.is_code_injection')}
    </div>
    <div class="text-xl font-bold">
      <CopyText text={selected.isCodeInjection.toString()}></CopyText>
    </div>
  </div>
</div>
