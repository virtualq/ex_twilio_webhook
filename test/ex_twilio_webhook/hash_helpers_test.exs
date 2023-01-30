defmodule ExTwilioWebhook.HashHelpersTest do
  use ExUnit.Case, async: true

  alias ExTwilioWebhook.HashHelpers

  describe "hmac_sha1_base64/2" do
    test "encodes data as expected" do
      body = "bodystring"
      key = "secret_key"
      expected = "lwSWI7Dl0gv2vrUxPYBgDj1qvlY="

      actual = HashHelpers.hmac_sha1_base64(key, body)
      assert actual == expected
    end
  end

  describe "add_port/1" do
    @input "https://api.example.com/twilio/conference_status.xml?waiter_id=42#rc=5&rp=all&sni=y"

    test "adds port :443 to https: urls" do
      actual = HashHelpers.add_port(@input)

      expected =
        "https://api.example.com:443/twilio/conference_status.xml?waiter_id=42#rc=5&rp=all&sni=y"

      assert actual == expected
    end
  end

  describe "get_sha_hash_from_url/1" do
    test "returns bodySHA256 param from the query if present" do
      signature = "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
      request_url = "https://mycompany.com/myapp.php?foo=1&bar=2"
      request_url_with_hash = "#{request_url}&bodySHA256=#{signature}"
      actual = HashHelpers.get_sha_hash_from_url(request_url_with_hash)
      assert actual == signature
    end

    test "returns nil when bodySHA256 is absent from the query" do
      request_url = "https://mycompany.com/myapp.php?foo=1&bar=2"
      actual = HashHelpers.get_sha_hash_from_url(request_url)
      assert is_nil(actual)
    end
  end

  describe "validate_request_with_body/4" do
    @json_body ~s[{"property": "value", "boolean": true}]
    @url "https://mycompany.com/myapp.php?foo=1&bar=2"

    @valid_body_signature "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
    @invalid_body_signature Base.encode16(:crypto.hash(:sha256, "invalid"))

    test "returns true for valid JSON body and request signatures" do
      request_url_with_hash = "#{@url}&bodySHA256=#{@valid_body_signature}"
      request_signature = "a9nBmqA0ju/hNViExpshrM61xv4="

      assert HashHelpers.validate_request_with_body(
               "12345",
               request_signature,
               request_url_with_hash,
               @json_body
             )
    end

    test "returns false for JSON body with invalid body signature" do
      request_url_with_hash = "#{@url}&bodySHA256=#{@invalid_body_signature}"
      request_signature = "a9nBmqA0ju/hNViExpshrM61xv4="

      refute HashHelpers.validate_request_with_body(
               "12345",
               request_signature,
               request_url_with_hash,
               @json_body
             )
    end

    test "returns false for JSON body with invalid request signature" do
      request_url_with_hash = "#{@url}&bodySHA256=#{@valid_body_signature}"
      request_signature = "a9nBmqA0ju/hNViEinvalid="

      refute HashHelpers.validate_request_with_body(
               "12345",
               request_signature,
               request_url_with_hash,
               @json_body
             )
    end

    @url_encoded_body "AccountSid=ACe497b94cea336b5d573d9667ffda50bf&AddOns=%7B+%22status%22%3A+%22successful%22%2C+%22message%22%3A+null%2C+%22code%22%3A+null%2C+%22results%22%3A+%7B+%7D+%7D&ApiVersion=2010-04-01&From=%2B15017122661&FromCity=SAN+FRANCISCO&FromCountry=US&FromState=CA&FromZip=94903&To=%2B15558675310&ToCity=SAN+FRANCISCO&ToCountry=US&ToState=CA&ToZip=94105&Body=Ahoy&MessageSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&NumMedia=0&NumSegments=1&ReferralNumMedia=0&SmsMessageSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&SmsSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&SmsStatus=received"

    @url "https://0447-85-232-252-1.eu.ngrok.io/twilio/conference_status?waiter_id=42"
    @token "c73504dac708a5cd9f57e80c747bb488"

    test "returns true for URL encoded request with valid signature" do
      signature = "cN6s/ajWzahiBNHjFpssnkbSQSM="

      assert HashHelpers.validate_request_with_body(@token, signature, @url, @url_encoded_body)
    end

    test "returns false for URL encoded request with invalid signature" do
      signature = "cN6s/ajWzahiBNHjFpssnkbaaaa="

      refute HashHelpers.validate_request_with_body(@token, signature, @url, @url_encoded_body)
    end
  end
end
