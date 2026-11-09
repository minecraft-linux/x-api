use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens.get_user().unwrap();
    let user_token = tokens.get_user_sts_token().unwrap();
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "scope=service::www.microsoft.com::mbi_ssl&uaid=411DB533-6AEF-4B99-8C15-95B6E1C5A2EA&clientid={d6d5a677-0872-4ab0-9442-bb792fce85c5}&ssoappgroup=none".to_owned(),
        Some(soap::PolicyReference::token_broker()),
    )
    .await
    .unwrap();

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "scope=service::www.microsoft.com::mbi_ssl&uaid=411DB533-6AEF-4B99-8C15-95B6E1C5A2EA&clientid={d6d5a677-0872-4ab0-9442-bb792fce85c5}&ssoappgroup=none".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token 2".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let user_token = match user_token {
        Token::Compact(t) => {
            if let Some(s) = t.strip_prefix("d=") {
                s.to_owned()
            } else {
                t
            }
        },
        _ => unreachable!(),
    };

    let (content, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .map_err(|err| err.to_string())?;

    println!("content req {:?}", content);
    println!("game_license req {:?}", game_license);
    

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .expect("could not parse base64 game SPLicense");

    let dev_license = tokens.get_device_license().unwrap();
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .expect("could not parse base64 device SPLicense");
    let key = device_license
        .encrypted_device_key
        .unwrap()
        .derive_device_key();
    Ok((key, game_splicense))
}
