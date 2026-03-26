use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

pub fn handle() -> Response<Full<Bytes>> {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(r#"{"status":"ok"}"#)))
        .unwrap()
}
