<script lang="ts">
  import LetterText from '@lucide/svelte/icons/letter-text';
  import Binary from '@lucide/svelte/icons/binary';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Scale from '@lucide/svelte/icons/scale';
  import SquareFunction from '@lucide/svelte/icons/square-function';

  import { type DetectionEvent } from '$lib/schemas/detection-events';

  let {
    selectedEvent = $bindable(),
    detectedEvents,
  }: { selectedEvent: DetectionEvent | null; detectedEvents: DetectionEvent[] } = $props();

  const updateSelection = (evt: DetectionEvent) => {
    selectedEvent = evt;
  };

  let displayId = $state(false);
</script>

<div class="border-base-300 flex h-full w-1/3 flex-col overflow-hidden rounded-xl border-1">
  <div class="bg-base-200 p-2">
    Selected: {selectedEvent?.OriginProcess}
    TODO: sort options
    <button
      class="btn btn-square"
      onclick={() => {
        displayId = !displayId;
      }}
    >
      <label class="swap swap-rotate">
        <input type="checkbox" bind:checked={displayId} disabled />
        <LetterText class="swap-off h-7 w-7" strokeWidth="0.7"></LetterText>
        <Binary class="swap-on h-7 w-7" strokeWidth="0.7"></Binary>
      </label>
    </button>
  </div>
  <ul class="h-full overflow-y-scroll">
    {#each detectedEvents as evt, i}
      {#if i === 0 || evt.DateAndTime.toDateString() !== detectedEvents[i - 1].DateAndTime.toDateString()}
        <li
          class="bg-base-100 border-b-base-300 sticky top-0 border-b-1 p-0.5 text-right font-semibold"
        >
          {evt.DateAndTime.toLocaleDateString()}
        </li>
      {/if}
      <li
        class="border-b-base-300 hover:bg-base-200 flex w-full cursor-pointer border-b-1 p-2 pt-0.5"
      >
        <div
          class="w-full"
          onclick={() => updateSelection(evt)}
          onkeyup={() => updateSelection(evt)}
          role="button"
          tabindex="0"
        >
          <div class="flex items-center gap-2">
            <div class="text-sm">{evt.DateAndTime.toLocaleTimeString()}</div>
            <div
              class="badge badge-md badge-{evt.Level.replace('Critical', 'Error').toLowerCase()}"
            >
              {evt.Level}
            </div>
            <div class="flex">
              <span class="font-semibold">
                {displayId ? evt.OriginPID : evt.OriginProcess}
              </span>
              <ChevronRight class="h-7" strokeWidth="1"></ChevronRight>
              <span>
                {displayId ? evt.TargetPID : evt.VictimProcess}
              </span>
            </div>
          </div>
          <div class="text-base-content flex flex-col gap-1 text-sm">
            <div class="flex items-center">
              <SquareFunction class="h-4 w-4" strokeWidth="0.7"></SquareFunction><span
                class="pr-2 pl-1 select-none">:</span
              >
              {displayId ? evt.GlobalDefensiveMethodId : evt.GlobalDefensiveMethod}
            </div>
            <div class="flex items-center">
              <Scale class="h-4 w-4" strokeWidth="0.7"></Scale><span class="pr-2 pl-1 select-none"
                >:</span
              >
              {evt.InvolvedYaraRule}
            </div>
          </div>
        </div>
      </li>
    {/each}
  </ul>
  <div class="bg-base-200 p-2">TODO: filter options</div>
</div>
