use super::*;

pub(super) fn packet_up_success_response(
    body_payload_is_empty: bool,
) -> Response<ResponseBody> {
    let mut response = simple_response(StatusCode::OK);
    if body_payload_is_empty {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

pub(super) async fn wait_for_stream_up_response_start(
    session_closed: CancellationToken,
    padding_enabled: bool,
    min_padding: usize,
    max_padding: usize,
) -> Option<(CancellationToken, Bytes)> {
    if padding_enabled {
        let padding_len = random_xray_range(min_padding, max_padding);
        return Some((session_closed, Bytes::from(vec![b'X'; padding_len])));
    }

    session_closed.cancelled().await;
    None
}

pub(super) async fn stream_up_response(
    session_closed: CancellationToken,
    state: &AppState,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let (min_secs, max_secs) = state.stream_up_server_secs;
    let padding_enabled = padding_enabled && max_secs > 0;

    let Some((session_closed, first_padding)) = wait_for_stream_up_response_start(
        session_closed,
        padding_enabled,
        state.min_padding,
        state.max_padding,
    )
    .await
    else {
        return stream_response(
            StatusCode::OK,
            futures::stream::empty::<Result<Frame<Bytes>, Infallible>>(),
            true,
        );
    };

    let min_padding = state.min_padding;
    let max_padding = state.max_padding;
    let shutdown = state.shutdown.clone();
    let body_stream = futures::stream::unfold(
        (session_closed, Some(first_padding)),
        move |(session_closed, first_padding)| {
            let shutdown = shutdown.clone();
            async move {
                if let Some(first_padding) = first_padding {
                    return Some((
                        Ok(Frame::data(first_padding)),
                        (session_closed, None),
                    ));
                }

                let delay_secs = random_xray_range(min_secs, max_secs);
                tokio::select! {
                    _ = session_closed.cancelled() => None,
                    _ = shutdown.cancelled() => None,
                    _ = sleep(Duration::from_secs(delay_secs as u64)) => {
                        let padding_len = random_xray_range(min_padding, max_padding);
                        Some((
                            Ok(Frame::data(Bytes::from(vec![b'X'; padding_len]))),
                            (session_closed, None),
                        ))
                    }
                }
            }
        },
    );

    stream_response(StatusCode::OK, body_stream, true)
}

pub(super) fn reader_response(
    status: StatusCode,
    reader: DuplexStream,
    no_sse_header: bool,
) -> Response<ResponseBody> {
    let body_stream = ReaderStream::new(reader).filter_map(|result| async move {
        match result {
            Ok(bytes) => Some(Ok(Frame::data(bytes))),
            Err(err) => {
                error!("xhttp response read failed: {}", err);
                None
            }
        }
    });
    stream_response(status, body_stream.boxed(), no_sse_header)
}

pub(super) fn stream_response<S>(
    status: StatusCode,
    body_stream: S,
    no_sse_header: bool,
) -> Response<ResponseBody>
where
    S: futures::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static,
{
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-accel-buffering", "no");
    if !no_sse_header {
        response = response.header(header::CONTENT_TYPE, "text/event-stream");
    }
    response
        .body(BodyExt::boxed_unsync(StreamBody::new(body_stream)))
        .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR))
}

pub(super) fn simple_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

pub(super) fn apply_xray_cors_headers(
    headers: &mut hyper::HeaderMap,
    request_method: &Method,
    request_headers: &hyper::HeaderMap,
    allow_credentials: bool,
) {
    // Current Xray mirrors the browser request Origin when present because
    // wildcard origins cannot be combined with credentialed cookie requests.
    let allow_origin = request_headers
        .get(header::ORIGIN)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);

    if allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if request_method == Method::OPTIONS {
        let allow_method = request_headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, allow_method);

        let allow_headers = request_headers
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers);
    }
}

pub(super) fn apply_response_padding(
    headers: &mut hyper::HeaderMap,
    state: &AppState,
) {
    let padding_len = random_xray_range(state.min_padding, state.max_padding);
    apply_response_padding_value(
        headers,
        state.padding_obfs_mode,
        state.padding_placement,
        &state.padding_key,
        &state.padding_header,
        state.padding_method,
        padding_len,
    );
}

pub(super) fn apply_response_padding_value(
    headers: &mut hyper::HeaderMap,
    padding_obfs_mode: bool,
    padding_placement: XhttpPaddingPlacement,
    padding_key: &str,
    padding_header: &str,
    padding_method: XhttpPaddingMethod,
    padding_len: usize,
) {
    if !padding_obfs_mode {
        if let Ok(value) =
            hyper::header::HeaderValue::from_str(&"X".repeat(padding_len))
        {
            headers.insert("x-padding", value);
        }
        return;
    }

    let padding = generate_padding(padding_method, padding_len);
    match padding_placement {
        XhttpPaddingPlacement::Cookie => {
            if !padding_key.is_empty()
                && !padding.is_empty()
                && let Ok(value) = hyper::header::HeaderValue::from_str(&format!(
                    "{padding_key}={padding}; Path=/"
                ))
            {
                headers.append(header::SET_COOKIE, value);
            }
        }
        // Current Xray has no response-side query padding representation.
        XhttpPaddingPlacement::Query => {}
        XhttpPaddingPlacement::Header => {
            if let Ok(name) =
                hyper::header::HeaderName::from_bytes(padding_header.as_bytes())
                && let Ok(value) = hyper::header::HeaderValue::from_str(&padding)
            {
                headers.insert(name, value);
            }
        }
        XhttpPaddingPlacement::QueryInHeader => {
            let value = format!("?{padding_key}={padding}");
            if let Ok(name) =
                hyper::header::HeaderName::from_bytes(padding_header.as_bytes())
                && let Ok(value) = hyper::header::HeaderValue::from_str(&value)
            {
                headers.insert(name, value);
            }
        }
    }
}
