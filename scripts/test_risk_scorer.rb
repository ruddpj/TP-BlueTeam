# frozen_string_literal: true

require_relative "risk_scorer"

class FakeEvent
  attr_reader :data, :tags

  def initialize(data = {})
    @data = data
    @tags = []
  end

  def get(path)
    path.scan(/\[([^\]]+)\]/).flatten.reduce(@data) do |value, key|
      value.is_a?(Hash) ? value[key] : nil
    end
  end

  def set(path, value)
    keys = path.scan(/\[([^\]]+)\]/).flatten
    parent = keys[0...-1].reduce(@data) do |current, key|
      current[key] ||= {}
    end
    parent[keys.last] = value
  end

  def tag(value)
    @tags << value
  end
end

class RiskScorerTest
  def assert_equal(expected, actual, description)
    return if expected == actual

    raise "#{description}: expected #{expected.inspect}, got #{actual.inspect}"
  end

  def test_scores_windows_process_chain_and_caps_score
    scorer = build_scorer
    event = FakeEvent.new(
      "process" => {
        "name" => 'C:\\Windows\\System32\\PowerShell.EXE',
        "parent" => { "name" => "C:\\Program Files\\Microsoft Office\\WINWORD.EXE" }
      },
      "event" => { "category" => ["Authentication"], "outcome" => "Failure" },
      "message" => "union select"
    )

    assert_equal [event], scorer.send(:filter, event), "filter return value"
    assert_equal 100, event.get("[event][risk_score]"), "capped risk score"
    assert_equal "high", event.get("[soc][risk][status]"), "high risk status"
    assert_equal(
      %w[authentication_failure suspicious_process_parent suspicious_payload_pattern],
      event.get("[soc][risk][reasons]"),
      "risk reasons"
    )
    assert_equal ["risk_assessed"], event.tags, "risk tag"
  end

  def test_records_threat_indicators_in_ecs_fields
    scorer = build_scorer
    event = FakeEvent.new(
      "source" => { "ip" => "203.0.113.8" },
      "destination" => { "ip" => "198.51.100.4" },
      "@metadata" => {
        "threat_intel" => {
          "source_ip" => "provider-a",
          "destination_ip" => "provider-a"
        }
      }
    )

    scorer.send(:filter, event)

    assert_equal 80, event.get("[event][risk_score]"), "threat intel risk score"
    assert_equal(
      ["203.0.113.8", "198.51.100.4"],
      event.get("[threat][indicator][ip]"),
      "threat indicator IPs"
    )
    assert_equal ["provider-a"], event.get("[threat][indicator][provider]"), "threat providers"
    assert_equal "ipv4-addr", event.get("[threat][indicator][type]"), "threat indicator type"
    assert_equal "high", event.get("[soc][risk][status]"), "high risk status"
  end

  def test_detects_url_encoded_payload_patterns
    scorer = build_scorer

    [
      "query=union%20select",
      "query=union+select",
      "path=..%2f..%2f..%2fetc/passwd"
    ].each do |url_path|
      event = FakeEvent.new("url" => { "path" => url_path })
      scorer.send(:filter, event)

      assert_equal 30, event.get("[event][risk_score]"), "encoded payload risk score for #{url_path}"
      assert_equal(
        ["suspicious_payload_pattern"],
        event.get("[soc][risk][reasons]"),
        "encoded payload reason for #{url_path}"
      )
    end
  end

  def test_uses_threshold_from_script_params
    scorer = build_scorer("25")
    event = FakeEvent.new(
      "event" => { "category" => ["authentication"], "outcome" => "failure" }
    )

    scorer.send(:filter, event)

    assert_equal "high", event.get("[soc][risk][status]"), "status at configured threshold"
  end

  def test_marks_unmatched_events_as_low
    scorer = build_scorer
    event = FakeEvent.new

    scorer.send(:filter, event)

    assert_equal 0, event.get("[event][risk_score]"), "unmatched risk score"
    assert_equal "low", event.get("[soc][risk][status]"), "low risk status"
    assert_equal [], event.get("[soc][risk][reasons]"), "unmatched risk reasons"
  end

  def test_rejects_out_of_range_threshold
    begin
      Object.new.send(:register, { "threshold" => "101" })
    rescue ArgumentError
      return
    end

    raise "out-of-range risk score threshold was accepted"
  end

  def run
    tests = %i[
      test_scores_windows_process_chain_and_caps_score
      test_records_threat_indicators_in_ecs_fields
      test_detects_url_encoded_payload_patterns
      test_uses_threshold_from_script_params
      test_marks_unmatched_events_as_low
      test_rejects_out_of_range_threshold
    ]
    tests.each { |test| public_send(test) }
    puts "#{tests.length} risk scorer tests passed"
  end

  private

  def build_scorer(threshold = "50")
    scorer = Object.new
    scorer.send(:register, { "threshold" => threshold })
    scorer
  end
end

RiskScorerTest.new.run
