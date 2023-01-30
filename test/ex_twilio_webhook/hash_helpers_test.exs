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
end
