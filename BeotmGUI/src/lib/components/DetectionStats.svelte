<script lang="ts">
  import { onMount } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  import { getEvents } from '$lib/logic/events-management.svelte';

  // TODO: @Spraduss have fun with those :)
  const events = getEvents(); // .loaded to have the list, .selected to get the selected one

  Chart.register(...registerables);

  let canvas: HTMLCanvasElement;

  onMount(() => {
    new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['A', 'B', 'C'],
        datasets: [
          {
            label: 'My Data',
            data: [10, 20, 15],
            backgroundColor: ['#4ade80', '#60a5fa', '#f87171'],
          },
        ],
      },
      options: { responsive: true },
    });
  });
</script>

<div class="border-base-300 bg-base-100 flex flex-1 flex-col overflow-auto rounded-xl border-1">
  <h1 class="p-2 font-bold text-4xl">Some stats</h1>
  <canvas bind:this={canvas}></canvas>
</div>

