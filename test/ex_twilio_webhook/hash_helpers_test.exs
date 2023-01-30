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
  end
end
