#include "Globals.h"

NTSTATUS WdfTcpipUtils::TcpipNotifyCallback(
	FWPS_CALLOUT_NOTIFY_TYPE type,
	const GUID* filterKey,
	const FWPS_FILTER* filter
) {
	UNREFERENCED_PARAMETER(type);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	DbgPrint("WFP: Notification triggered.\n");
	return STATUS_SUCCESS;
}

VOID WdfTcpipUtils::TcpipFlowDeleteCallback(
	UINT16 layerId,
	UINT32 calloutId,
	UINT64 flowContext
) {
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);

	DbgPrint("WFP: Flow deleted.\n");
}

VOID WdfTcpipUtils::TcpipFilteringCallback(
	const FWPS_INCOMING_VALUES* values,
	const FWPS_INCOMING_METADATA_VALUES0* metadata,
	PVOID layerData,
	const void* context,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	UNREFERENCED_PARAMETER(metadata);
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(values);

	//classifyOut->actionType = FWP_ACTION_PERMIT; // Permit the traffic

	UINT32 localAddress = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remoteAddress = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

	if (remote_port == 1234) {
		classifyOut->actionType = FWP_ACTION_BLOCK; // Deny the traffic
	}
	else {
		classifyOut->actionType = FWP_ACTION_PERMIT;

		DbgPrint("\t%d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu\n",
			FORMAT_ADDR(localAddress),
			local_port,
			FORMAT_ADDR(remoteAddress),
			remote_port
		);
	}
}

NTSTATUS WdfTcpipUtils::AddSubLayer() {
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.displayData.name = L"OutboundConnectionSubLayer";
	sublayer.displayData.description = L"Handles outbound connections";
	sublayer.subLayerKey = BEOTM_SUBLAYER_GUID;
	sublayer.weight = 0;

	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

VOID WdfTcpipUtils::UnitializeWfp() {

	if (EngineHandle != NULL) {

		if (FilterId != 0) {
			FwpmFilterDeleteById(EngineHandle, FilterId);
			FwpmSubLayerDeleteByKey(EngineHandle, &BEOTM_SUBLAYER_GUID);
		}

		if (AddCalloutId != 0) {
			FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
		}

		if (RegCalloutId != 0) {
			FwpsCalloutUnregisterById(RegCalloutId);
		}

		FwpmEngineClose(EngineHandle);
	}
}

NTSTATUS WdfTcpipUtils::WfpRegisterCallout() {

	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT s_callout = { 0 };		

	FWPM_CALLOUT m_callout = { 0 };				

	FWPM_DISPLAY_DATA display_data = { 0 };

	display_data.name = L"BeotmWdfCallout";
	display_data.description = L"BeotmWdfCallout";

	s_callout.calloutKey = BEOTM_CALLOUT_GUID;
	s_callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN3)WdfTcpipUtils::TcpipFilteringCallback;
	s_callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN3)WdfTcpipUtils::TcpipNotifyCallback;
	s_callout.flowDeleteFn = (FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)WdfTcpipUtils::TcpipFlowDeleteCallback;

	status = FwpsCalloutRegister((void*)DeviceObject, &s_callout, &RegCalloutId);

	if (!NT_SUCCESS(status)) {
		DbgPrint("FwpsCalloutRegister failed with status 0x%x\n", status);
		return status;
	}

	m_callout.calloutKey = BEOTM_CALLOUT_GUID;
	m_callout.displayData = display_data;
	m_callout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
	m_callout.flags = 0;

	status = FwpmCalloutAdd(EngineHandle, &m_callout, NULL, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[+] FwpmCalloutAdd failed with status 0x%x\n", status);
		return status;
	}
	else {
		DbgPrint("[+] FwpmCalloutAdd success\n");
	}

	return status;
}

NTSTATUS WdfTcpipUtils::WfpAddFilter() {

	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };

	filter.displayData.name = L"BeotmDefaultFilter";
	filter.displayData.description = L"BeotmDefaultFilter";
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = BEOTM_SUBLAYER_GUID;
	filter.subLayerKey = BEOTM_SUBLAYER_GUID;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xf;
	filter.numFilterConditions = 0;
	filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
	filter.action.calloutKey = BEOTM_CALLOUT_GUID;

	status = FwpmFilterAdd(EngineHandle, &filter, NULL, &FilterId);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[X] Failed to add filter\n");
		return status;
	}
	else {
		DbgPrint("[+] Filter added\n");
	}

	return status;
}


NTSTATUS WdfTcpipUtils::WfpAddSubLayer() {

	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER subLayer = { 0 };

	subLayer.subLayerKey = BEOTM_SUBLAYER_GUID;
	subLayer.displayData.name = L"BeotmSubLayer";
	subLayer.displayData.description = L"BeotmSubLayer";
	subLayer.flags = 0;
	subLayer.weight = 0x0f;

	status = FwpmSubLayerAdd(EngineHandle, &subLayer, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[X] Failed to add sublayer\n");
		return status;
	}
	else {
		DbgPrint("[+] Sublayer added\n");
	}

	return status;
}

NTSTATUS WdfTcpipUtils::InitWfp() {

	NTSTATUS status;

	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);

	if (!NT_SUCCESS(status)) {
		goto failure;
	}

	status = WfpRegisterCallout();

	if (!NT_SUCCESS(status)) {
		goto failure;
	}


	status = WfpAddSubLayer();

	if (!NT_SUCCESS(status)) {
		goto failure;
	}

	status = WfpAddFilter();

	if (!NT_SUCCESS(status)) {
		goto failure;
	}

	DbgPrint("[+] WFP initialized\n");

	return STATUS_SUCCESS;

failure:
	DbgPrint("[X] Failed to initialize WFP\n");
	UnitializeWfp();
	return status;

}