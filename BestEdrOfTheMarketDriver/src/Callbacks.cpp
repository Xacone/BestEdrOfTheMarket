#include "Globals.h"

BufferQueue* CallbackObjects::bufferQueue = nullptr;
HashQueue* CallbackObjects::hashQueue = nullptr;
BytesQueue* CallbackObjects::bytesQueue = nullptr;

VOID CallbackObjects::setupNotificationsGlobal() {

	this->setThreadNotificationCallback();

	this->setProcessNotificationCallback();

	this->setImageNotificationCallback();
}

VOID CallbackObjects::unsetNotificationsGlobal() {

	this->unsetThreadNotificationCallback();

	this->unsetProcessNotificationCallback();

	this->unsetImageNotificationCallback();
}