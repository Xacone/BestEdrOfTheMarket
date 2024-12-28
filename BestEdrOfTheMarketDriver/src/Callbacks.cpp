#include "Globals.h"

BufferQueue* CallbackObjects::queue = nullptr;

VOID CallbackObjects::setupNotificationsGlobal() {

	this->setThreadNotificationCallback();

	this->setProcessNotificationCallback();
}

VOID CallbackObjects::unsetNotificationsGlobal() {

	this->unsetThreadNotificationCallback();

	this->unsetProcessNotificationCallback();
}