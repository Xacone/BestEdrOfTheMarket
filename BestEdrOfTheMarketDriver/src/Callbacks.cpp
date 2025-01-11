#include "Globals.h"

BufferQueue* CallbackObjects::bufferQueue = nullptr;
HashQueue* CallbackObjects::hashQueue = nullptr;
BytesQueue* CallbackObjects::bytesQueue = nullptr;

PVOID CallbackObjects::DriverObject = nullptr;

VOID CallbackObjects::setupNotificationsGlobal() {

	this->setThreadNotificationCallback();

	this->setProcessNotificationCallback();

	this->setImageNotificationCallback();

	this->setObjectNotificationCallback();

	this->setRegistryNotificationCallback();
}

VOID CallbackObjects::unsetNotificationsGlobal() {

	this->unsetThreadNotificationCallback();

	this->unsetProcessNotificationCallback();

	this->unsetImageNotificationCallback();

	this->unsetObjectNotificationCallback();

	this->unsetRegistryNotificationCallback();
}