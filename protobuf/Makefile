
all:
	protoc --java_out=../java/src/main/java/ SignalService.proto Provisioning.proto WebSocketResources.proto StickerResources.proto
	protoc --java_out=../java/src/main/java/ UnidentifiedDelivery.proto
	protoc --java_out=../java/src/main/java/ WhisperTextProtocol.proto LocalStorageProtocol.proto FingerprintProtocol.proto