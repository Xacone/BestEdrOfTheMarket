<script lang="ts">
  import CopyText from '../CopyText.svelte';
  import SpecificInfoViewer from './SpecificInfoViewer.svelte';
  const { data } = $props();
</script>

<div class={['grid', 'grid-cols-5']}>
  {#each data as [key, value], index}
    <div
      class={[
        'p-1',
        'col-span-2',
        'border-l-[0.5px]',
        'border-b-[0.5px]',
        index % 2 === 0 ? 'bg-base-200' : 'bg-base-100',
      ]}
    >
      {key}
    </div>
    <div class="col-span-3 flex flex-col">
      {#if value !== null && typeof value === 'object'}
        <SpecificInfoViewer data={Object.entries(value)}></SpecificInfoViewer>
      {:else}
        <div
          class={[
            'p-1',
            'border-l-[0.5px]',
            'border-b-[0.5px]',
            'font-bold',
            index % 2 === 0 ? 'bg-base-200' : 'bg-base-100',
          ]}
        >
          <CopyText text={value}></CopyText>
        </div>
      {/if}
    </div>
  {/each}
</div>
