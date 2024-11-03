use std::sync::Arc;

use http::header::{HOST, USER_AGENT};
use http::uri::PathAndQuery;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use mutual_tls::ConnectionContext;

pub async fn handle(
    mut req: Request<Incoming>,
    ctx: ConnectionContext,
    downstream: Arc<str>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method();
    let uri = req.uri();
    let host = req.headers().get(HOST);
    let user_agent = req.headers().get(USER_AGENT);

    tracing::info!(%method, %uri, ?host, ?user_agent, common_name = ?ctx.common_name, "handling a request");

    let client: Client<HttpConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build_http();

    let path_and_query = uri.path_and_query().map_or("/", PathAndQuery::as_str);

    *req.uri_mut() = format!("{downstream}{path_and_query}").parse().unwrap();

    let res = client.request(req).await.unwrap().map(BoxBody::new);

    Ok(res)
}
