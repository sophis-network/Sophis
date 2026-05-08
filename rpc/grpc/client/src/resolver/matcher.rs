use sophis_grpc_core::protowire::{SophisdRequest, SophisdResponse, sophisd_request, sophisd_response};

pub(crate) trait Matcher<T> {
    fn is_matching(&self, response: T) -> bool;
}

impl Matcher<&sophisd_response::Payload> for sophisd_request::Payload {
    fn is_matching(&self, response: &sophisd_response::Payload) -> bool {
        use sophisd_request::Payload;
        match self {
            // TODO: implement for each payload variant supporting request/response pairing
            Payload::GetBlockRequest(request) => {
                if let sophisd_response::Payload::GetBlockResponse(response) = response {
                    if let Some(block) = response.block.as_ref() {
                        if let Some(verbose_data) = block.verbose_data.as_ref() {
                            return verbose_data.hash == request.hash;
                        }
                        return true;
                    } else if let Some(error) = response.error.as_ref() {
                        // the response error message should contain the requested hash
                        return error.message.contains(request.hash.as_str());
                    }
                }
                false
            }

            _ => true,
        }
    }
}

impl Matcher<&SophisdResponse> for SophisdRequest {
    fn is_matching(&self, response: &SophisdResponse) -> bool {
        if let Some(ref response) = response.payload
            && let Some(ref request) = self.payload
        {
            return request.is_matching(response);
        }
        false
    }
}
