<script lang="ts">
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Scale from '@lucide/svelte/icons/scale';
  import SquareFunction from '@lucide/svelte/icons/square-function';
  import { LevelBadge } from '$lib/schemas/graphical-event';
  import { type DetectionEvent } from '$lib/schemas/detection-events';

  let {
    evt,
    selectedEvent = $bindable(),
    filterArea,
  }: {
    evt: DetectionEvent;
    selectedEvent: DetectionEvent | null;
    filterArea: HTMLInputElement | undefined;
  } = $props();

  const isSelection = (evt: DetectionEvent) => selectedEvent === evt;
  const updateSelection = (evt: DetectionEvent) => (selectedEvent = isSelection(evt) ? null : evt);
</script>

<li class="border-b-base-300 flex w-full border-b">
  <button
    class="w-full cursor-pointer border-l-6 p-2 pt-0.5
    {isSelection(evt)
      ? 'bg-base-200 border-l-primary hover:bg-base-300'
      : 'bg-base-100 hover:bg-base-200 border-l-transparent'} 
      "
    onclick={() => updateSelection(evt)}
    onkeydown={(e) => {
      if (e.key === 'ArrowRight') {
        e.preventDefault();
        filterArea?.focus();
      }
    }}
  >
    <div class="flex flex-wrap items-center gap-x-2">
      <div class="text-sm">{evt.DateAndTime.toLocaleTimeString()}</div>
      <div class="badge badge-md {LevelBadge[evt.Level]}">
        {evt.Level}
      </div>
      <div class="flex-end flex grow justify-start">
        <span class="font-semibold">
          {evt.OriginProcess}
        </span>
        <ChevronRight class="h-7" strokeWidth="1"></ChevronRight>
        <span>
          {evt.VictimProcess}
        </span>
      </div>
    </div>
    <div class="text-base-content flex flex-col gap-1 text-sm">
      <div class="flex items-center">
        <SquareFunction class="h-4 w-4" strokeWidth="0.7"></SquareFunction><span
          class="pr-2 pl-1 select-none">:</span
        >
        {evt.GlobalDefensiveMethod}
      </div>
      <div class="flex items-center">
        <Scale class="h-4 w-4" strokeWidth="0.7"></Scale><span class="pr-2 pl-1 select-none">:</span
        >
        {evt.InvolvedYaraRule}
      </div>
    </div>
  </button>
</li>
