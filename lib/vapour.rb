require 'openssl'
require 'cgi'
require 'time'
require 'base64'
require 'net/http'
require 'json'
require 'pp'

require 'nokogiri'

class Vapour
  Error = Class.new(RuntimeError)

  NS = {'aws' => 'http://cloudformation.amazonaws.com/doc/2010-05-15/'}
  DIGEST = OpenSSL::Digest::Digest.new("sha256")

  def initialize(key, secret)
    @aws_key = key
    @aws_secret = secret
    @url = URI('https://cloudformation.eu-west-1.amazonaws.com/')
  end

  # +name+
  #   The name associated with the stack. The name must be unique within your
  #   AWS account.
  #
  # DisableRollbac
  #   Boolean to enable or disable rollback on stack creation failures.
  #   Default: false
  #
  # NotificationARNs.member.N
  #   The Simple Notification Service (SNS) topic ARNs to publish stack related
  #   events. You can find your SNS topic ARNs using the SNS console or your
  #   Command Line Interface (CLI).
  #
  # Parameters.member.N
  #   A list of Parameter structures.
  #
  # TemplateBody
  #   Structure containing the template body. (For more information, go to the
  #   AWS CloudFormation User Guide.)
  #
  #   Condition: You must pass TemplateBody or TemplateURL. If both are passed,
  #   only TemplateBody is used.
  #
  # TemplateURL
  #   Location of file containing the template body. The URL must point to a
  #   template located in an S3 bucket in the same region as the stack. For
  #   more information, go to the AWS CloudFormation User Guide.
  #   Conditional: You must pass TemplateURL or TemplateBody. If both are
  #   passed, only TemplateBody is used.
  #
  # TimeoutInMinutes
  #   The amount of time that can pass before the stack status becomes
  #   CREATE_FAILED; if DisableRollback is not set or is set to false, the
  #   stack will be rolled back.
  def create_stack(name, options = {})
    given = options.dup
    query = {'Action' => 'CreateStack', 'StackName' => name}

    if parameters = given.delete('Parameters')
      parameters.each_with_index do |(key, value), idx|
        query["Parameters.member.#{idx + 1}.ParameterKey"] = key
        query["Parameters.member.#{idx + 1}.ParameterValue"] = value
      end
    end

    if notifications = given.delete('NotificationARNs')
      notifications.each_with_index do |member, idx|
        query["NotificationARNs.member.#{idx + 1}"] = member
      end
    end

    query.merge!(given)

    request(query)
  end

  def describe_stacks(name = nil)
    query = {'Action' => 'DescribeStacks'}
    query['StackName'] = name if name
    Stack.create_from_response(request(query))
  end

  # options are:
  #   LogicalResourceId
  #   PhysicalResourceId
  #   StackName
  def describe_stack_resources(query = {})
    pass = {'Action' => 'DescribeStackResources'}.merge(query)
    request(pass)
  end

  # Validates a specified template.
  def validate_template_body(body)
    request('Action' => 'ValidateTemplate',
            'TemplateBody' => body)
  end

  # Validates a specified template.
  def validate_template_url(url)
    request('Action' => 'ValidateTemplate',
            'TemplateURL' => url)
  end

  def request(query)
    url, data = prepare_url(query)

    request = Net::HTTP::Post.new(url.path)
    request['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
    request.body = sign_request('POST', url, data)
    response = Net::HTTP.start(url.host, url.port, :use_ssl => true){|http| http.request(request) }

    case response
    when Net::HTTPSuccess
      handle_success(response)
    else
      handle_error(response)
    end
  end

  def prepare_url(query)
    url = @url.dup
    data = {
      'Version' => '2010-05-15',
      'SignatureVersion' => 2,
      'AWSAccessKeyId' => @aws_key,
    }.merge(query)

    return url, data
  end

  def handle_success(response)
    Nokogiri::XML(response.body)
  end

  def handle_error(response)
    xml = Nokogiri::XML(response.body)
    error = xml.xpath('//aws:ErrorResponse', NS)
    type = error.xpath('//aws:Type', NS).text
    code = error.xpath('//aws:Code', NS).text
    message = error.xpath('//aws:Message', NS).text
    raise Error, "Type: #{type}, Code: #{code}, Message: #{message}"
  end

  def sign_request(verb, url, data)
    data['Timestamp'] ||= Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z') unless data["Expires"]
    data["SignatureVersion"] = 2
    data['SignatureMethod'] = 'HmacSHA256'

    query_string = data.sort_by{|key, value| key }.map{|key, value|
      [escape(key), escape(value)].join('=')
    }.join('&')

    string = [verb.to_s.upcase, url.host.downcase, url.path, query_string].join("\n")
    hmac = OpenSSL::HMAC.digest(DIGEST, @aws_secret, string)
    signature = CGI.escape(Base64.encode64(hmac).strip)
    "#{query_string}&Signature=#{signature}"
  end

  def escape(query_param)
    CGI.escape(query_param.to_s).
      gsub("%7E", "~").
      gsub("+", "%20").
      gsub("*", "%2A")
  end

  class Stack < Struct.new(
    :id, :status, :description, :name, :creation_time, :disable_rollback,
    :status_reason, :parameters, :outputs
  )
    MEMBER_XPATH = '//aws:DescribeStacksResponse/aws:DescribeStacksResult/aws:Stacks/aws:member'

    def self.create_from_response(response)
      stack_members = response.xpath(MEMBER_XPATH, NS)
      stack_members.map do |stack_member|
        instance = new(
          stack_member.xpath('aws:StackId', NS).text,
          stack_member.xpath('aws:StackStatus', NS).text,
          stack_member.xpath('aws:Description', NS).text,
          stack_member.xpath('aws:StackName', NS).text,
          Time.iso8601(stack_member.xpath('aws:CreationTime', NS).text),
          stack_member.xpath('aws:DisableRollback', NS).text == 'true',
          stack_member.xpath('aws:StackStatusReason', NS).text,
          {},
          {}, 
        )
        stack_member.xpath('aws:Parameters/aws:member', NS).each do |member|
          key = member.xpath('aws:ParameterKey', NS).text
          value = member.xpath('aws:ParameterValue', NS).text
          instance.parameters[key] = value
        end

        stack_member.xpath('aws:Outputs/aws:member', NS).each do |member|
          key = member.xpath('aws:OutputKey', NS).text
          value = member.xpath('aws:OutputValue', NS).text
          instance.outputs[key] = value
        end

        instance
      end
    end
  end
end

if __FILE__ == $0
  key = ENV['AWS_ACCESS_KEY_ID']
  secret = ENV['AWS_SECRET_ACCESS_KEY']
  vapour = Vapour.new(key, secret)
  # vapour.create_stack('TestingFirst', 'TemplateBody' => File.read('template3.json'), 'Parameters' => { 'KeyPair' => '123', 'Version' => '22' })

  p vapour.describe_stacks.map{|stack| [stack.name, stack.parameters['Version']] }
  # puts vapour.describe_stack_resources('StackName' => 'sns2')
end
