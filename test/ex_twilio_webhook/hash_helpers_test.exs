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

  describe "build_url_with_standard_port/1" do
    @input "https://api.example.com/twilio/conference_status.xml?waiter_id=42#rc=5&rp=all&sni=y"

    test "adds port :443 to https: urls" do
      actual = HashHelpers.build_url_with_standard_port(@input)

      expected =
        "https://api.example.com:443/twilio/conference_status.xml?waiter_id=42#rc=5&rp=all&sni=y"

      assert actual == expected
    end
  end
end
