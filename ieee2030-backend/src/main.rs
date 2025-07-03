use chrono::Utc;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{info, warn};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

struct Metrics {
    requests_total: AtomicU64,
    get_requests: AtomicU64,
    post_requests: AtomicU64,
    start_time: Instant,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            get_requests: AtomicU64::new(0),
            post_requests: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

struct Server {
    metrics: Arc<Metrics>,
}

impl Server {
    fn new() -> Self {
        Self {
            metrics: Arc::new(Metrics::new()),
        }
    }

    async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> std::result::Result<Response<BoxBody>, Infallible> {
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        let method = req.method().clone();
        let path = req.uri().path();

        let result = match method {
            Method::GET => {
                self.metrics.get_requests.fetch_add(1, Ordering::Relaxed);
                self.handle_get(path).await
            }
            Method::POST => {
                self.metrics.post_requests.fetch_add(1, Ordering::Relaxed);
                self.handle_post(req).await
            }
            _ => Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(empty())
                .unwrap()),
        };

        match result {
            Ok(response) => Ok(response),
            Err(_) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full("Internal Server Error"))
                .unwrap()),
        }
    }

    async fn handle_get(&self, path: &str) -> Result<Response<BoxBody>> {
        match path {
            "/dcap" => Ok(xml_response(get_device_capability())),
            "/tm" => Ok(xml_response(get_time())),
            "/edev" => Ok(xml_response(get_end_device_list())),
            "/dr" => Ok(xml_response(get_dr_program_list())),
            "/mr" => Ok(xml_response(get_metering_list())),
            "/pricing" => Ok(xml_response(get_pricing_info())),
            "/health" => self.handle_health().await,
            "/chunked" => self.handle_chunked().await,
            "/der_controls" => Ok(xml_response(get_der_control_list())),
            "/der_controls_invalid" => Ok(xml_response(get_invalid_der_control_list())),
            "/load_controls" => Ok(xml_response(get_load_control_list())),
            "/end_device_controls" => Ok(xml_response(get_end_device_control_list())),
            path if path.starts_with("/edev/") => {
                let device_id = path.strip_prefix("/edev/").unwrap_or("1");
                Ok(xml_response(get_end_device(device_id)))
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("Resource not found"))
                .unwrap()),
        }
    }

    async fn handle_post(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody>> {
        let path = req.uri().path().to_string();
        let _body = req.collect().await?.to_bytes();

        match path.as_str() {
            "/edev" => {
                let device_id: u32 = rand::random::<u32>() % 9000 + 1000;
                let location = format!("/edev/{}", device_id);

                Ok(Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Content-Type", "application/sep+xml")
                    .header("Location", &location)
                    .body(full(create_end_device_response(device_id)))
                    .unwrap())
            }
            path if path.starts_with("/edev/") => {
                let device_id = path.strip_prefix("/edev/").unwrap_or("1");
                Ok(xml_response(update_end_device_response(device_id)))
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("Resource not found"))
                .unwrap()),
        }
    }

    async fn handle_health(&self) -> Result<Response<BoxBody>> {
        let uptime = self.metrics.start_time.elapsed().as_secs();
        let total_requests = self.metrics.requests_total.load(Ordering::Relaxed);
        let get_requests = self.metrics.get_requests.load(Ordering::Relaxed);
        let post_requests = self.metrics.post_requests.load(Ordering::Relaxed);

        let health_data = json!({
            "status": "ok",
            "timestamp": Utc::now().to_rfc3339(),
            "uptime_seconds": uptime,
            "metrics": {
                "total_requests": total_requests,
                "get_requests": get_requests,
                "post_requests": post_requests,
                "requests_per_second": if uptime > 0 { total_requests / uptime } else { 0 }
            }
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(full(health_data.to_string()))
            .unwrap())
    }

    async fn handle_chunked(&self) -> Result<Response<BoxBody>> {
        let chunked_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<MeterReadingList xmlns="http://zigbee.org/sep">
    <MeterReading><mRID>1</mRID><Reading><value>1000</value></Reading></MeterReading>
    <MeterReading><mRID>2</mRID><Reading><value>1050</value></Reading></MeterReading>
    <MeterReading><mRID>3</mRID><Reading><value>1100</value></Reading></MeterReading>
</MeterReadingList>"#;

        Ok(xml_response(chunked_xml.to_string()))
    }
}

fn xml_response(body: String) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/sep+xml")
        .header("Connection", "keep-alive")
        .body(full(body))
        .unwrap()
}

fn empty() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn get_device_capability() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
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
</DeviceCapability>"#
        .to_string()
}

fn get_time() -> String {
    let current_time = Utc::now().timestamp();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Time xmlns="http://zigbee.org/sep">
    <currentTime>{}</currentTime>
    <dstEndTime>1667714400</dstEndTime>
    <dstOffset>3600</dstOffset>
    <dstStartTime>1615698000</dstStartTime>
    <localTime>{}</localTime>
    <quality>7</quality>
</Time>"#,
        current_time, current_time
    )
}

fn get_end_device_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
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
</EndDeviceList>"#
        .to_string()
}

fn get_end_device(device_id: &str) -> String {
    let category = device_id.parse::<u32>().unwrap_or(1) % 3;
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{}">
    <lFDI>246AC5E76F1B2B5C7E8F9A0B1C2D3E4F</lFDI>
    <sFDI>1234{}</sFDI>
    <deviceCategory>{}</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{}/fsa" all="2"/>
</EndDevice>"#,
        device_id, device_id, category, device_id, device_id, device_id
    )
}

fn get_dr_program_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
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
</DemandResponseProgramList>"#
        .to_string()
}

fn get_metering_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<MeteringProgramList xmlns="http://zigbee.org/sep" all="1" results="1">
    <MeteringProgram href="/mr/1">
        <mRID>MP001</mRID>
        <description>Residential Metering</description>
        <primacy>1</primacy>
        <MeterReadingListLink href="/mr/1/readings" all="10"/>
        <ReadingTypeListLink href="/mr/1/rt" all="5"/>
    </MeteringProgram>
</MeteringProgramList>"#
        .to_string()
}

fn get_pricing_info() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
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
</TariffProfileList>"#
        .to_string()
}

fn create_end_device_response(device_id: u32) -> String {
    let current_time = Utc::now().timestamp();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{}">
    <sFDI>198325674429</sFDI>
    <lFDI>49e1cf69294c0588202f4f2cbd4f80044902ca51</lFDI>
    <changedTime>{}</changedTime>
    <deviceCategory>0f</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{}/fsa" all="2"/>
</EndDevice>"#,
        device_id, current_time, device_id, device_id, device_id
    )
}

fn update_end_device_response(device_id: &str) -> String {
    let current_time = Utc::now().timestamp();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="urn:ieee:std:2030.5:ns" href="/edev/{}">
    <sFDI>198325674429</sFDI>
    <lFDI>49e1cf69294c0588202f4f2cbd4f80044902ca51</lFDI>
    <changedTime>{}</changedTime>
    <deviceCategory>0f</deviceCategory>
    <DeviceInformation>
        <mfModel>SmartMeter2000</mfModel>
        <mfSerialNumber>SM{}001</mfSerialNumber>
        <primaryPower>1</primaryPower>
        <secondaryPower>0</secondaryPower>
    </DeviceInformation>
    <DeviceInformationLink href="/edev/{}/di"/>
    <FunctionSetAssignmentsListLink href="/edev/{}/fsa" all="2"/>
</EndDevice>"#,
        device_id, current_time, device_id, device_id, device_id
    )
}

fn get_der_control_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<DERControlList xmlns="urn:ieee:std:2030.5:ns" all="2" results="2">
    <DERControl href="/der_controls/1">
        <mRID>DER001</mRID>
        <description>Valid DER Control - 10 minutes</description>
        <interval>600</interval>
        <startTime>2025-06-18T14:00:00Z</startTime>
        <duration>600</duration>
        <randomizeStart>60</randomizeStart>
        <randomizeDuration>30</randomizeDuration>
        <DERControlBase>
            <opModConnect>true</opModConnect>
            <opModEnergize>true</opModEnergize>
        </DERControlBase>
    </DERControl>
    <DERControl href="/der_controls/2">
        <mRID>DER002</mRID>
        <description>Valid DER Control - 15 minutes</description>
        <interval>900</interval>
        <startTime>2025-06-18T15:00:00Z</startTime>
        <duration>900</duration>
        <DERControlBase>
            <opModConnect>true</opModConnect>
            <opModEnergize>false</opModEnergize>
        </DERControlBase>
    </DERControl>
</DERControlList>"#
        .to_string()
}

fn get_invalid_der_control_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<DERControlList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">
    <DERControl href="/der_controls/invalid">
        <mRID>DER_INVALID</mRID>
        <description>Invalid DER Control - Too short (2 minutes)</description>
        <interval>120</interval>
        <startTime>2025-06-18T14:00:00Z</startTime>
        <duration>120</duration>
        <DERControlBase>
            <opModConnect>true</opModConnect>
            <opModEnergize>true</opModEnergize>
        </DERControlBase>
    </DERControl>
</DERControlList>"#
        .to_string()
}

fn get_load_control_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<LoadControlList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">
    <LoadControl href="/load_controls/1">
        <mRID>LC001</mRID>
        <description>Load Control - 20 minutes</description>
        <interval>1200</interval>
        <startTime>2025-06-18T16:00:00Z</startTime>
        <duration>1200</duration>
        <deviceCategory>0x01</deviceCategory>
        <LoadControlEvent>
            <creationTime>1737206400</creationTime>
            <interval>1200</interval>
            <deviceCategory>0x01</deviceCategory>
        </LoadControlEvent>
    </LoadControl>
</LoadControlList>"#
        .to_string()
}

fn get_end_device_control_list() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<EndDeviceControlList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">
    <EndDeviceControl href="/end_device_controls/1">
        <mRID>EDC001</mRID>
        <description>End Device Control - 8 minutes</description>
        <interval>480</interval>
        <startTime>2025-06-18T17:00:00Z</startTime>
        <duration>480</duration>
        <deviceCategory>0x02</deviceCategory>
        <drProgramMRID>DRP001</drProgramMRID>
    </EndDeviceControl>
</EndDeviceControlList>"#
        .to_string()
}

#[tokio::main]

async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let port = if args.len() > 1 {
        args[1].parse::<u16>().unwrap_or_else(|_| {
            eprintln!("Invalid port number '{}', using default 8888", args[1]);
            8888
        })
    } else {
        8888
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    info!(
        "IEEE 2030.5 High-Performance Backend Server starting on http://{}",
        addr
    );
    info!("Endpoints:");
    info!("  GET  /dcap                - Device Capability");
    info!("  GET  /tm                  - Time");
    info!("  GET  /edev                - End Device List");
    info!("  GET  /edev/{{id}}            - Specific End Device");
    info!("  GET  /dr                  - Demand Response Programs");
    info!("  GET  /mr                  - Metering Programs");
    info!("  GET  /pricing             - Tariff/Pricing Info");
    info!("  GET  /chunked             - Chunked XML Response");
    info!("  GET  /health              - Health Check (JSON with metrics)");
    info!("  POST /edev                - Create End Device");
    info!("  POST /edev/{{id}}           - Update End Device");
    info!("");
    info!("CONTROL VALIDATION TEST ENDPOINTS:");
    info!("  GET  /der_controls        - Valid DER Controls (should pass validation)");
    info!("  GET  /der_controls_invalid - Invalid DER Controls (should fail validation)");
    info!("  GET  /load_controls       - Load Controls");
    info!("  GET  /end_device_controls - End Device Controls");

    let server = Arc::new(Server::new());

    loop {
        let (stream, _) = listener.accept().await?;
        let server = Arc::clone(&server);

        tokio::task::spawn(async move {
            let io = TokioIo::new(stream);

            if let Err(err) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let server = Arc::clone(&server);
                        async move { server.handle_request(req).await }
                    }),
                )
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
}
