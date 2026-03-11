macro_rules! try_extract {
    ($variant:path, $from:expr) => {{
        if let $variant(_temp) = $from {
            Ok(_temp)
        } else {
            Err(::anyhow::anyhow!(
                "Failed to extract {} from {}",
                stringify!($variant),
                stringify!($from),
            ))
        }
    }};
}

pub(crate) use try_extract;
