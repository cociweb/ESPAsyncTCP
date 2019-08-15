#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <ArduinoOTA.h>
#include <ESPAsyncTCP.h>
#include <SyncClient.h>

#include "credentials.h"

void setup(){
  Serial.begin(115200);
  Serial.setDebugOutput(true);
  Serial.flush();
  Serial.println(">>> starting SyncClient.ino test sketch");
  WiFi.persistent(false);
  WiFi.begin(ssid, password);
  if (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.printf("WiFi Failed!\n");
    return;
  }
  Serial.printf("WiFi Connected!\n");
  Serial.println(WiFi.localIP());
  ArduinoOTA.begin();
  
  SyncClient client;

  {
    SSL_CTX_PARAMS params;
    params.use_insecure = true;
    params.iobuf_in_size = 4096;
    params.display("setup()", Serial);
    client.setSSLParams(params);
  }

  if(!client.connect("canihazip.com", 443, true)){
    Serial.println("Connect Failed");
    return;
  }
  Serial.printf("free heap = %5d\n", system_get_free_heap_size());
  client.setTimeout(2);
  if(client.printf("GET /s HTTP/1.1\r\nHost: canihazip.com\r\nConnection: close\r\n\r\n") > 0){
    while(client.connected() && client.available() == 0){
      delay(1);
    }
    Serial.printf("free heap = %5d\n", system_get_free_heap_size());
    while(client.available()){
      Serial.write(client.read());
    }
    if(client.connected()){
      client.stop();
    }
    Serial.printf("free heap = %5d\n", system_get_free_heap_size());
  } else {
    client.stop();
    Serial.println("Send Failed");
    while(client.connected()) delay(0);
  }
  Serial.printf("free heap = %5d\n", system_get_free_heap_size());
}

void loop(){
  ArduinoOTA.handle();
  delay(1000);
  Serial.printf("free heap = %5d\n", system_get_free_heap_size());
}
