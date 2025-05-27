#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
import socket
from datetime import datetime, timezone

class IEEE2030Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'  # Enable HTTP/1.1 keep-alive support
    
    def __init__(self, *args, **kwargs):
        self.close_connection = False
        super().__init__(*args, **kwargs)
    
    def handle(self):
        """Override to handle multiple requests on same connection"""
        self.close_connection = False
        request_count = 0
        
        try:
            while not self.close_connection and request_count < 100:  # Limit requests per connection
                request_count += 1
                print(f"\n--- Handling request #{request_count} on connection {id(self)} ---")
                
                self.handle_one_request()
                
                if self.close_connection:
                    print(f"Connection marked for closing after {request_count} requests")
                    break
                    
                print(f"Keeping connection alive after request #{request_count}")
                
        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"Client closed connection after {request_count} requests: {e}")
        except Exception as e:
            print(f"Error handling connection: {e}")
            import traceback
            traceback.print_exc()
        finally:
            print(f"Connection {id(self)} closed after {request_count} requests")
    
    def end_headers(self):
        """Override to add keep-alive headers"""
        if not self.close_connection:
            self.send_header('Connection', 'keep-alive')
            self.send_header('Keep-Alive', 'timeout=60, max=100')  # 60 second timeout, max 100 requests
        else:
            self.send_header('Connection', 'close')
        super().end_headers()

    def log_request_details(self, method):
        """Log detailed request information for debugging"""
        print(f"\n=== {method} REQUEST DEBUG (Connection {id(self)}) ===")
        print(f"Path: {self.path}")
        print(f"Command: {self.command}")
        print(f"Request version: {self.request_version}")
        print(f"Client address: {self.client_address}")
        print("Headers:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")
        print("=== END REQUEST DEBUG ===\n")

    def do_POST(self):
        """Handle POST requests for creating/updating resources"""
        try:
            self.log_request_details("POST")
            
            content_length = self.headers.get('Content-Length')
            print(f"Content-Length header: {content_length}")
            
            if content_length is None:
                print("ERROR: No Content-Length header found!")
                self.send_error(400, "Missing Content-Length header")
                return
                
            content_length = int(content_length)
            print(f"Content-Length as int: {content_length}")
            
            if content_length > 0:
                print(f"Reading {content_length} bytes from request body...")
                post_data = self.rfile.read(content_length).decode('utf-8')
                print(f"POST data received ({len(post_data)} chars):")
                print(f"'{post_data}'")
            else:
                post_data = ""
                print("No POST data (Content-Length is 0)")
            
            print(f"Checking path: {self.path}")
            
            if self.path == '/edev':
                print("Calling create_end_device...")
                self.create_end_device(post_data)
            elif self.path.startswith('/edev/'):
                device_id = self.path.split('/')[-1]
                print(f"Calling update_end_device for device {device_id}...")
                self.update_end_device(device_id, post_data)
            else:
                print(f"Unknown path: {self.path}")
                self.send_error(404, "Resource not found")
                
        except Exception as e:
            print(f"ERROR in do_POST: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, f"Internal server error: {e}")

    def create_end_device(self, xml_data):
        """Handle end device creation"""
        try:
            print(f"\n=== CREATE END DEVICE ===")
            print(f"Received XML data length: {len(xml_data)}")
            print(f"XML Data: '{xml_data}'")
            
            # Generate a new device ID (simple counter for demo)
            import random
            new_device_id = random.randint(1000, 9999)
            print(f"Generated new device ID: {new_device_id}")
            
            # Return the created device with a 201 Created status
            print("Sending 201 Created response...")
            self.send_response(201)  # Created
            self.send_header('Content-Type', 'application/sep+xml')
            self.send_header('Location', f'/edev/{new_device_id}')
            
            response_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{new_device_id}">
    <sFDI>198325674429</sFDI>
    <lFDI>49e1cf69294c0588202f4f2cbd4f80044902ca51</lFDI>
    <changedTime>1379905200</changedTime>
    <deviceCategory>0f</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{new_device_id}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{new_device_id}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{new_device_id}/fsa" all="2"/>
</EndDevice>'''
            
            print(f"Response XML length: {len(response_xml.encode())}")
            self.send_header('Content-Length', str(len(response_xml.encode())))
            
            # Check if client wants to close connection
            connection_header = self.headers.get('Connection', '').lower()
            if connection_header == 'close':
                self.close_connection = True
                print("Client requested connection close")
            
            self.end_headers()
            print("Headers sent, writing response body...")
            self.wfile.write(response_xml.encode())
            print("Response sent successfully!")
            print("=== END CREATE END DEVICE ===\n")
            
        except Exception as e:
            print(f"ERROR in create_end_device: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, f"Error creating device: {e}")

    def update_end_device(self, device_id, xml_data):
        """Handle end device updates"""
        print(f"Received EndDevice update request for device {device_id}:")
        print(f"XML Data: {xml_data}")
        
        # Return updated device
        self.send_response(200)  # OK
        self.send_header('Content-Type', 'application/sep+xml')
        
        response_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{device_id}">
    <sFDI>198325674429</sFDI>
    <lFDI>49e1cf69294c0588202f4f2cbd4f80044902ca51</lFDI>
    <changedTime>{int(datetime.now(timezone.utc).timestamp())}</changedTime>
    <deviceCategory>0f</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{device_id}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{device_id}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{device_id}/fsa" all="2"/>
</EndDevice>'''
        
        self.send_header('Content-Length', str(len(response_xml.encode())))
        
        # Check if client wants to close connection
        connection_header = self.headers.get('Connection', '').lower()
        if connection_header == 'close':
            self.close_connection = True
            print("Client requested connection close")
            
        self.end_headers()
        self.wfile.write(response_xml.encode())

    def do_GET(self):
        try:
            self.log_request_details("GET")
            
            if self.path == '/dcap':
                # Device Capability - Root resource
                print("Serving /dcap")
                self.send_xml_response(self.get_device_capability())
                
            elif self.path == '/tm':
                # Time - Current server time
                print("Serving /tm")
                self.send_xml_response(self.get_time())
                
            elif self.path == '/edev':
                # End Device List
                print("Serving /edev")
                self.send_xml_response(self.get_end_device_list())
                
            elif self.path.startswith('/edev/'):
                # Specific End Device
                device_id = self.path.split('/')[-1]
                print(f"Serving /edev/{device_id}")
                self.send_xml_response(self.get_end_device(device_id))
                
            elif self.path == '/dr':
                # Demand Response Program List
                print("Serving /dr")
                self.send_xml_response(self.get_dr_program_list())
                
            elif self.path == '/mr':
                # Metering Reading List
                print("Serving /mr")
                self.send_xml_response(self.get_metering_list())
                
            elif self.path == '/pricing':
                # Pricing Information
                print("Serving /pricing")
                self.send_xml_response(self.get_pricing_info())
                
            elif self.path == '/chunked':
                # Chunked XML response
                print("Serving /chunked")
                self.send_chunked_xml()
                
            elif self.path == '/health':
                # Health check endpoint
                print("Serving /health")
                self.send_health_response()
                
            else:
                # 404 for unknown paths
                print(f"Unknown path: {self.path}")
                self.send_error(404, "Resource not found")
                
        except Exception as e:
            print(f"ERROR in do_GET: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, f"Internal server error: {e}")

    def send_xml_response(self, xml_content):
        """Send XML response with proper headers"""
        try:
            print(f"Sending XML response, length: {len(xml_content.encode())}")
            self.send_response(200)
            self.send_header('Content-Type', 'application/sep+xml')
            self.send_header('Content-Length', str(len(xml_content.encode())))
            
            # Check if client wants to close connection
            connection_header = self.headers.get('Connection', '').lower()
            if connection_header == 'close':
                self.close_connection = True
                print("Client requested connection close")
                
            self.end_headers()
            self.wfile.write(xml_content.encode())
            print("XML response sent successfully")
        except Exception as e:
            print(f"ERROR in send_xml_response: {e}")
            import traceback
            traceback.print_exc()

    def send_health_response(self):
        """Send health check response"""
        health_data = {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime": time.time() - server_start_time,
            "connection_id": id(self)
        }
        
        import json
        response_body = json.dumps(health_data, indent=2)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body.encode())))
        self.end_headers()
        self.wfile.write(response_body.encode())

    def send_chunked_xml(self):
        """Send chunked XML response to simulate streaming data"""
        self.send_response(200)
        self.send_header('Transfer-Encoding', 'chunked')
        self.send_header('Content-Type', 'application/sep+xml')
        self.end_headers()

        # XML header
        xml_start = '<?xml version="1.0" encoding="UTF-8"?>\n<MeterReadingList xmlns="http://zigbee.org/sep">\n'
        chunk = xml_start.encode()
        self.wfile.write(f"{len(chunk):x}\r\n".encode())
        self.wfile.write(chunk)
        self.wfile.write(b"\r\n")

        # Send meter readings in chunks
        for i in range(3):
            reading_xml = f'  <MeterReading><mRID>{i+1}</mRID><Reading><value>{1000 + i*50}</value></Reading></MeterReading>\n'
            chunk = reading_xml.encode()
            self.wfile.write(f"{len(chunk):x}\r\n".encode())
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
            time.sleep(0.5)  # Simulate slow data

        # XML footer
        xml_end = '</MeterReadingList>\n'
        chunk = xml_end.encode()
        self.wfile.write(f"{len(chunk):x}\r\n".encode())
        self.wfile.write(chunk)
        self.wfile.write(b"\r\n")

        # End chunks
        self.wfile.write(b"0\r\n\r\n")

    # ... (keep all the existing get_* methods unchanged)
    def get_device_capability(self):
        """IEEE 2030.5 Device Capability XML"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<DeviceCapability xmlns="urn:ieee:std:2030.5:ns">
    <href>/dcap</href>
    <pollRate>900</pollRate>
    <EndDeviceListLink href="/edev" all="10"/>
    <MirrorUsagePointListLink href="/mup" all="5"/>
    <SelfDeviceLink href="/sdev"/>
    <DemandResponseProgramListLink href="/dr" all="3"/>
    <MeteringProgramListLink href="/mr" all="2"/>
    <TimeLink href="/tm"/>
    <TariffProfileListLink href="/pricing" all="1"/>
</DeviceCapability>'''

    def get_time(self):
        """Current time in IEEE 2030.5 format"""
        current_time = int(datetime.now(timezone.utc).timestamp())
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<Time xmlns="http://zigbee.org/sep">
    <currentTime>{current_time}</currentTime>
    <dstEndTime>1667714400</dstEndTime>
    <dstOffset>3600</dstOffset>
    <dstStartTime>1615698000</dstStartTime>
    <localTime>{current_time}</localTime>
    <quality>7</quality>
</Time>'''

    def get_end_device_list(self):
        """List of end devices (smart meters, etc.)"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<EndDeviceList xmlns="urn:ieee:std:2030.5:ns" all="3" results="3">
    <EndDevice href="/edev/1">
        <lFDI>246AC5E76F1B2B5C7E8F9A0B1C2D3E4F</lFDI>
        <sFDI>12345</sFDI>
        <deviceCategory>0</deviceCategory>
        <DeviceInformationLink href="/edev/1/di"/>
        <FunctionSetAssignmentsListLink href="/edev/1/fsa" all="2"/>
    </EndDevice>
    <EndDevice href="/edev/2">
        <lFDI>357BD6F87G2C3C6D8F9G0H1I2J3K4L5M</lFDI>
        <sFDI>12346</sFDI>
        <deviceCategory>1</deviceCategory>
        <DeviceInformationLink href="/edev/2/di"/>
        <FunctionSetAssignmentsListLink href="/edev/2/fsa" all="1"/>
    </EndDevice>
    <EndDevice href="/edev/3">
        <lFDI>468CE7G98H3D4D7E9G0H1I2J3K4L5M6N</lFDI>
        <sFDI>12347</sFDI>
        <deviceCategory>2</deviceCategory>
        <DeviceInformationLink href="/edev/3/di"/>
        <FunctionSetAssignmentsListLink href="/edev/3/fsa" all="3"/>
    </EndDevice>
</EndDeviceList>'''

    def get_end_device(self, device_id):
        """Specific end device information"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{device_id}">
    <lFDI>246AC5E76F1B2B5C7E8F9A0B1C2D3E4F</lFDI>
    <sFDI>1234{device_id}</sFDI>
    <deviceCategory>{int(device_id) % 3}</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{device_id}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{device_id}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{device_id}/fsa" all="2"/>
</EndDevice>'''

    def get_dr_program_list(self):
        """Demand Response Program List"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<DemandResponseProgramList xmlns="http://zigbee.org/sep" all="2" results="2">
    <DemandResponseProgram href="/dr/1">
        <mRID>DRP001</mRID>
        <description>Peak Demand Reduction</description>
        <primacy>1</primacy>
        <ActiveDemandResponseControlListLink href="/dr/1/drc" all="1"/>
    </DemandResponseProgram>
    <DemandResponseProgram href="/dr/2">
        <mRID>DRP002</mRID>
        <description>Emergency Load Shed</description>
        <primacy>2</primacy>
        <ActiveDemandResponseControlListLink href="/dr/2/drc" all="0"/>
    </DemandResponseProgram>
</DemandResponseProgramList>'''

    def get_metering_list(self):
        """Metering Program List"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<MeteringProgramList xmlns="http://zigbee.org/sep" all="1" results="1">
    <MeteringProgram href="/mr/1">
        <mRID>MP001</mRID>
        <description>Residential Metering</description>
        <primacy>1</primacy>
        <MeterReadingListLink href="/mr/1/readings" all="10"/>
        <ReadingTypeListLink href="/mr/1/rt" all="5"/>
    </MeteringProgram>
</MeteringProgramList>'''

    def get_pricing_info(self):
        """Tariff/Pricing Information"""
        current_time = int(datetime.now(timezone.utc).timestamp())
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<TariffProfileList xmlns="http://zigbee.org/sep" all="1" results="1">
    <TariffProfile href="/pricing/1">
        <mRID>TP001</mRID>
        <description>Time of Use Pricing</description>
        <pricePowerOfTenMultiplier>-2</pricePowerOfTenMultiplier>
        <currency>840</currency>
        <RateComponentListLink href="/pricing/1/rc" all="3"/>
        <TimeTariffIntervalListLink href="/pricing/1/tti" all="24"/>
        <ConsumptionTariffIntervalListLink href="/pricing/1/cti" all="5"/>
    </TariffProfile>
</TariffProfileList>'''

class DualStackHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        # Enable dual stack (IPv4 and IPv6)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

# Global server start time for uptime calculation
server_start_time = time.time()

if __name__ == '__main__':
    try:
        # Try IPv6 dual-stack first
        server = DualStackHTTPServer(('::', 8888), IEEE2030Handler)
        print("IEEE 2030.5 Utility Server Simulator running on http://localhost:8888")
        print("  IPv4: http://127.0.0.1:8888")
        print("  IPv6: http://[::1]:8888")
    except:
        # Fallback to IPv4 only
        server = HTTPServer(('127.0.0.1', 8888), IEEE2030Handler)
        print("IEEE 2030.5 Utility Server Simulator running on http://127.0.0.1:8888")
    
    print("\nIEEE 2030.5 Endpoints:")
    print("  /dcap     - Device Capability (root)")
    print("  /tm       - Time")
    print("  /edev     - End Device List")
    print("  /edev/1   - Specific End Device")
    print("  /dr       - Demand Response Programs")
    print("  /mr       - Metering Programs")
    print("  /pricing  - Tariff/Pricing Info")
    print("  /chunked  - Chunked XML Response")
    print("  /health   - Health Check (JSON)")
    print("\nContent-Type: application/sep+xml")
    print("Keep-Alive: Enabled (timeout=60s, max=100 requests)")
    
    server.serve_forever()