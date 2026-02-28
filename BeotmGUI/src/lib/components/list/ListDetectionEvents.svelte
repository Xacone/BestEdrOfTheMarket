<script lang="ts">
  import CalendarArrowDown from '@lucide/svelte/icons/calendar-arrow-down';
  import CalendarArrowUp from '@lucide/svelte/icons/calendar-arrow-up';
  import FunnelPlus from '@lucide/svelte/icons/funnel-plus';
  import { t } from 'svelte-i18n';

  import { getEvents } from '$lib/logic/events-management.svelte';
  import ListCard from './ListCard.svelte';
  import type { DetectionEvent } from '$lib/schemas/detection-events';

  const events = getEvents();

  // TODO: improve performance: keep a max capacity of loaded events and  load new events when scrolling to the top/bottom (show a spinner) (and unload previous events)
  let listEvents = $state([...events.loaded]);
  let mostRecentTopSort = $state(true);
  let filterText = $state('');
  let filterArea: HTMLInputElement | undefined = $state<HTMLInputElement>();

  // TODO: make this configurable
  const source = 'http://127.0.0.1:3000';

  const stringFieldFilter = (field: keyof DetectionEvent) => {
    return (evt: DetectionEvent, filterValue: string) => {
      return evt[field]
        .toString()
        .toLowerCase()
        .replace(' ', '_')
        .includes(filterValue.toLowerCase());
    };
  };

  // could be improved, but good enough atm
  const filterJSONContent = (content: any, filterValue: string) =>
    JSON.stringify(content).toLowerCase().includes(filterValue.toLowerCase());

  const filterMethods = {
    origin: (evt: DetectionEvent, filterValue: string) =>
      filterJSONContent(
        {
          name: evt['OriginProcess'],
          pid: evt['OriginPID'],
          path: evt['OriginProcessImagePath'],
        },
        filterValue,
      ),
    target: (evt: DetectionEvent, filterValue: string) =>
      filterJSONContent(
        {
          name: evt['VictimProcess'],
          pid: evt['TargetPID'],
        },
        filterValue,
      ),
    method: stringFieldFilter('GlobalDefensiveMethod'),
    yara: stringFieldFilter('InvolvedYaraRule'),
    level: stringFieldFilter('Level'),
    source: stringFieldFilter('Source'),
    specifics: (evt: DetectionEvent, filterValue: string) =>
      filterJSONContent(evt['SpecificEventsInfo'], filterValue),
    // TODO: add more fields / methods
  };
  type FilterKey = keyof typeof filterMethods;

  const filterKeys = Object.keys(filterMethods) as FilterKey[];

  $effect(() => {
    const parsingKeys = filterText
      .split(' ')
      .map((el) => el.split(':'))
      .filter((pair) => pair.length == 2 && filterKeys.includes(pair[0] as FilterKey));

    const filteredEvents = filterText
      ? events.loaded.filter((evt) =>
          parsingKeys
            .map((pair) => filterMethods[pair[0] as FilterKey](evt, pair[1]))
            .every(Boolean),
        )
      : events.loaded;

    const sortedEvents = mostRecentTopSort ? [...filteredEvents].reverse() : [...filteredEvents];
    listEvents = sortedEvents;
  });
</script>

<div
  class="border-base-300 flex h-full w-3/10 min-w-75 flex-col overflow-visible rounded-xl border"
>
  <div class="bg-base-200 flex items-center justify-between rounded-t-xl p-2 text-sm">
    <div>
      {#if listEvents.length == events.loaded.length}
        {$t('list_event.received_count')}: <span class="font-bold"> {events.loaded.length} </span>
      {:else}
        {'Filtered events'}:
        <span class="font-bold"> {listEvents.length} </span> / {events.loaded.length}
      {/if}
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
        <li class="bg-base-100 border-b-base-300 sticky top-0 border-b text-right font-semibold">
          {evt.DateAndTime.toLocaleDateString()}
        </li>
      {/if}
      <ListCard {evt} bind:selectedEvent={events.selected} {filterArea}></ListCard>
    {/each}
  </ul>
  <div class="bg-base-200 flex items-center justify-around rounded-b-xl p-2">
    <!-- TODO: add suggestions after typing ':' (like for level: 'critical', 'Info', 'Warning' should appear)-->
    <!-- also (later): replace this footer by a banner saying 'selected' when selecting events in the dashboard (deal with dashboard selection) -->
    <input
      type="text"
      placeholder={$t('list_event.filter_events')}
      bind:value={filterText}
      bind:this={filterArea}
      class="input outline-none"
    />
    <label title={$t('list_event.add_filter')}>
      <button class="btn" popovertarget="popover-1" style="anchor-name:--anchor-1">
        <FunnelPlus class="h-5" strokeWidth="0.7"></FunnelPlus>
      </button>
    </label>
    <ul
      class="dropdown dropdown-top menu rounded-box bg-base-100 w-52 shadow-sm"
      popover
      id="popover-1"
      style="position-anchor:--anchor-1"
    >
      {#each filterKeys as key}
        <li>
          <button
            onclick={() => {
              filterText += ` ${key}:`;
              filterArea?.focus();
            }}>{key}</button
          >
        </li>
      {/each}
    </ul>
  </div>
</div>
