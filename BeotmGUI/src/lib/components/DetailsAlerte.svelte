<script lang="ts">
    export let eventClickedForMoreDetails;
</script>

<style>
  .div-1 {
        background-color: #EBEBEB;
    }
</style>

<div class="div-1 w-200 pl-5">
    {#if eventClickedForMoreDetails !== null}
    <p>{ eventClickedForMoreDetails.DateAndTime.toDateString() }</p>
    <p>{ eventClickedForMoreDetails.Version }</p>
    {/if}
</div>