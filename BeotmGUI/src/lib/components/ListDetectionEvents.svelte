<script lang="ts">
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Scale from '@lucide/svelte/icons/scale';
  import SquareFunction from '@lucide/svelte/icons/square-function';
  import CalendarArrowDown from '@lucide/svelte/icons/calendar-arrow-down';
  import CalendarArrowUp from '@lucide/svelte/icons/calendar-arrow-up';
  import { t } from 'svelte-i18n';

  import { type DetectionEvent } from '$lib/schemas/detection-events';
  import { LevelBadge } from '$lib/schemas/graphical-event';
  import { getEvents } from '$lib/logic/events-management.svelte';

  const events = getEvents();

  const isSelection = (evt: DetectionEvent) => events.selected === evt;

  const updateSelection = (evt: DetectionEvent) =>
    (events.selected = isSelection(evt) ? null : evt);

  let listEvents = $state([...events.loaded]);
  let mostRecentTopSort = $state(true);
  let filter = $state('');

  $effect(() => {
    // Possible improvement with tags ( severity, method, yara...)
    const filteredEvents = filter
      ? events.loaded.filter((evt) => {
          return JSON.stringify(evt).toLocaleLowerCase().includes(filter.toLocaleLowerCase());
        })
      : events.loaded;
    const sortedEvents = mostRecentTopSort ? [...filteredEvents].reverse() : [...filteredEvents];
    listEvents = sortedEvents;
  });
</script>

<div
  class="border-base-300 flex h-full w-3/10 min-w-[300px] flex-col overflow-hidden rounded-xl border-1"
>
  <div class="bg-base-200 flex items-center justify-between p-2 text-sm">
    <div>
      {$t('list_event.received_count')}: {events.loaded.length}
    </div>
    <label
      class="btn btn-circle swap swap-rotate"
      title={$t(`list_event.sort_${mostRecentTopSort ? 'oldest' : 'recent'}`)}
    >
      <input
        type="checkbox"
        onclick={() => {
          mostRecentTopSort = !mostRecentTopSort;
        }}
      />
      <CalendarArrowDown class="swap-off h-5" strokeWidth="0.7"></CalendarArrowDown>
      <CalendarArrowUp class="swap-on h-5" strokeWidth="0.7"></CalendarArrowUp>
    </label>
  </div>
  <ul class="h-full overflow-y-scroll">
    {#each listEvents as evt, i}
      {#if i === 0 || evt.DateAndTime.toDateString() !== listEvents[i - 1].DateAndTime.toDateString()}
        <li class="bg-base-100 border-b-base-300 sticky top-0 border-b-1 text-right font-semibold">
          {evt.DateAndTime.toLocaleDateString()}
        </li>
      {/if}
      <li class="border-b-base-300 flex w-full border-b-1">
        <button
          class="w-full cursor-pointer p-2 pt-0.5 {isSelection(evt)
            ? 'bg-base-300 hover:bg-base-200'
            : 'bg-base-100 hover:bg-base-200'}"
          onclick={() => updateSelection(evt)}
        >
          <div class="flex flex-wrap items-center gap-x-2">
            <div class="text-sm">{evt.DateAndTime.toLocaleTimeString()}</div>
            <div class="badge badge-md {LevelBadge[evt.Level]}">
              {evt.Level}
            </div>
            <div class="flex-end flex grow-1 justify-start">
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
              <Scale class="h-4 w-4" strokeWidth="0.7"></Scale><span class="pr-2 pl-1 select-none"
                >:</span
              >
              {evt.InvolvedYaraRule}
            </div>
          </div>
        </button>
      </li>
    {/each}
  </ul>
  <div class="bg-base-200 p-2">
    <input type="text" placeholder="Filter options" bind:value={filter} class="input" />
  </div>
</div>
