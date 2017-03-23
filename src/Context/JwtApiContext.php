<?php

namespace Behat\JwtApiExtension\Context;

use Behat\Gherkin\Node\PyStringNode;
use Behat\Gherkin\Node\TableNode;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;
use PHPUnit_Framework_Assert as Assertions;

class JwtApiContext implements ApiClientAwareInterface
{

    /**
     * @var string
     */
    protected $authorization;

    /**
     * @var ClientInterface
     */
    protected $client;

    /**
     * @var array
     */
    protected $headers = array();

    /**
     * @var \GuzzleHttp\Message\RequestInterface
     */
    protected $request;

    /**
     * @var \GuzzleHttp\Message\ResponseInterface
     */
    protected $response;

    protected $placeHolders = array();
    
    /**
     * @var array
     */
    protected $config;

    public function setConfig(array $config)
    {
        $this->config = $config;
    }

    /**
     * Adds JWT Authentication header in the request.
     *
     * @param string $username
     *
     * @Then /^I am authenticating with jwt token as "([^"]*)"$/
     */
    public function iAmAuthenticatingWithJWT($username)
    {
        $this->removeHeader('Authorization');

        $key = \JWT::encode(
            [
                $this->config['encoded_field_name'] => $username,
                'exp' => time()+$this->config['ttl']
            ]
        , $this->config['secret_key']);

        $this->addHeader($this->config['header_name'], $this->config['token_prefix'].$key);
    }

    /**
     * Validate Jwt token
     *
     * @param string $token_field_name
     *
     * @Then /^(?:the )?response should contain jwt token in field "([^"]*)"$/
     */
    public function responseShouldContainJwtToken($token_field_name)
    {
        $response = $this->response->json();

        Assertions::assertArrayHasKey($token_field_name, $response);
        $tks = explode('.', $response[$token_field_name]);
        Assertions::assertEquals(3 , count($tks));

        list($headb64, $bodyb64, $cryptob64) = $tks;

        $sig = \JWT::urlsafeB64Decode($cryptob64);
        $header = \JWT::jsonDecode(\JWT::urlsafeB64Decode($headb64));

        Assertions::assertTrue(\JWT::verify("$headb64.$bodyb64", $sig, $this->config['secret_key'], $header->alg));
    }

    /**
     * Validate Jwt token data
     *
     * @param string $token_field_name
     * @param PyStringNode $jsonString
     *
     * @Then /^(?:the )?response should contain jwt token in field "([^"]*)" with data:$/
     */
    public function responseShouldContainJwtTokenInFieldWithData($token_field_name, PyStringNode $jsonString)
    {
        $expected = json_decode($this->replacePlaceHolder($jsonString->getRaw()), true);

        $response = $this->response->json();
        Assertions::assertArrayHasKey($token_field_name, $response);

        $actual = \JWT::decode($response[$token_field_name], $this->config['secret_key']);

        foreach ($expected as $key => $needle) {
            Assertions::assertObjectHasAttribute($key, $actual);
            Assertions::assertEquals($expected[$key], $actual->{$key});
        }
    }

    /**
     * {@inheritdoc}
     */
    public function setClient(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Adds Basic Authentication header to next request.
     *
     * @param string $username
     * @param string $password
     *
     * @Given /^I am authenticating as "([^"]*)" with "([^"]*)" password$/
     */
    public function iAmAuthenticatingAs($username, $password)
    {
        $this->removeHeader('Authorization');
        $this->authorization = base64_encode($username . ':' . $password);
        $this->addHeader('Authorization', 'Basic ' . $this->authorization);
    }

    /**
     * Sets a HTTP Header.
     *
     * @param string $name  header name
     * @param string $value header value
     *
     * @Given /^I set header "([^"]*)" with value "([^"]*)"$/
     */
    public function iSetHeaderWithValue($name, $value)
    {
        $this->addHeader($name, $value);
    }

    /**
     * Sends HTTP request to specific relative URL.
     *
     * @param string $method request method
     * @param string $url    relative url
     *
     * @When /^(?:I )?send a ([A-Z]+) request to "([^"]+)"$/
     */
    public function iSendARequest($method, $url)
    {
        $url = $this->prepareUrl($url);
//        $this->request = $this->getClient()->createRequest($method, $url);
//        if (!empty($this->headers)) {
//            $this->request->addHeaders($this->headers);
//        }

         if (version_compare(ClientInterface::VERSION, '6.0', '>=')) {
            $this->request = new Request($method, $url, $this->headers);
        } else {
            $this->request = $this->getClient()->createRequest($method, $url);
            if (!empty($this->headers)) {
                $this->request->addHeaders($this->headers);
            }
        }
        $this->sendRequest();
    }

    /**
     * Sends HTTP request to specific URL with field values from Table.
     *
     * @param string    $method request method
     * @param string    $url    relative url
     * @param TableNode $post   table of post values
     *
     * @When /^(?:I )?send a ([A-Z]+) request to "([^"]+)" with values:$/
     */
    public function iSendARequestWithValues($method, $url, TableNode $post)
    {
        $url = $this->prepareUrl($url);
        $fields = array();

        foreach ($post->getRowsHash() as $key => $val) {
            $fields[$key] = $this->replacePlaceHolder($val);
        }

        $bodyOption = array(
            'body' => json_encode($fields),
        );
        
        if (version_compare(ClientInterface::VERSION, '6.0', '>=')) {
            $this->request = new Request($method, $url, $this->headers, $bodyOption['body']);
        } else {
            $this->request = $this->getClient()->createRequest($method, $url, $bodyOption);
            if (!empty($this->headers)) {
                $this->request->addHeaders($this->headers);
            }
        }

        $this->sendRequest();
    }

    /**
     * Sends HTTP request to specific URL with raw body from PyString.
     *
     * @param string       $method request method
     * @param string       $url    relative url
     * @param PyStringNode $string request body
     *
     * @When /^(?:I )?send a ([A-Z]+) request to "([^"]+)" with body:$/
     */
    public function iSendARequestWithBody($method, $url, PyStringNode $string)
    {
        $url = $this->prepareUrl($url);
        $string = $this->replacePlaceHolder(trim($string));

        if (version_compare(ClientInterface::VERSION, '6.0', '>=')) {
            $this->request = new Request($method, $url, $this->headers, $string);
        } else {
            $this->request = $this->getClient()->createRequest(
                $method,
                $url,
                array(
                    'headers' => $this->getHeaders(),
                    'body' => $string,
                )
            );
        }
        $this->sendRequest();
    }

    /**
     * Sends HTTP request to specific URL with form data from PyString.
     *
     * @param string       $method request method
     * @param string       $url    relative url
     * @param PyStringNode $body   request body
     *
     * @When /^(?:I )?send a ([A-Z]+) request to "([^"]+)" with form data:$/
     */
    public function iSendARequestWithFormData($method, $url, PyStringNode $body)
    {
        $url = $this->prepareUrl($url);
        $body = $this->replacePlaceHolder(trim($body));

        $fields = array();
        parse_str(implode('&', explode("\n", $body)), $fields);
        if (version_compare(ClientInterface::VERSION, '6.0', '>=')) {
            $this->request = new Request($method, $url, ['Content-Type' => 'application/x-www-form-urlencoded'], http_build_query($fields, null, '&'));
        } else {
            $this->request = $this->getClient()->createRequest($method, $url);
            /** @var \GuzzleHttp\Post\PostBodyInterface $requestBody */
            $requestBody = $this->request->getBody();
            foreach ($fields as $key => $value) {
                $requestBody->setField($key, $value);
            }
        }

        $this->sendRequest();
    }

    /**
     * Checks that response has specific status code.
     *
     * @param string $code status code
     *
     * @Then /^(?:the )?response code should be (\d+)$/
     */
    public function theResponseCodeShouldBe($code)
    {
        $expected = intval($code);
        $actual = intval($this->response->getStatusCode());
        Assertions::assertSame($expected, $actual);
    }

    /**
     * Checks that response body contains specific text.
     *
     * @param string $text
     *
     * @Then /^(?:the )?response should contain "([^"]*)"$/
     */
    public function theResponseShouldContain($text)
    {
        $expectedRegexp = '/' . preg_quote($text) . '/i';
        $actual = (string) $this->response->getBody();
        Assertions::assertRegExp($expectedRegexp, $actual);
    }

    /**
     * Checks that response body doesn't contains specific text.
     *
     * @param string $text
     *
     * @Then /^(?:the )?response should not contain "([^"]*)"$/
     */
    public function theResponseShouldNotContain($text)
    {
        $expectedRegexp = '/' . preg_quote($text) . '/';
        $actual = (string) $this->response->getBody();
        Assertions::assertNotRegExp($expectedRegexp, $actual);
    }

    /**
     * Checks that response body contains JSON from PyString.
     *
     * Do not check that the response body /only/ contains the JSON from PyString,
     *
     * @param PyStringNode $jsonString
     *
     * @throws \RuntimeException
     *
     * @Then /^(?:the )?response should contain json:$/
     */
    public function theResponseShouldContainJson(PyStringNode $jsonString)
    {
        $etalon = json_decode($this->replacePlaceHolder($jsonString->getRaw()), true);
        $actual = $this->response->json();

        if (null === $etalon) {
            throw new \RuntimeException(
              "Can not convert etalon to json:\n" . $this->replacePlaceHolder($jsonString->getRaw())
            );
        }
        if (null === $actual) {
            throw new \RuntimeException(
              "Can not convert actual to json:\n" . $this->replacePlaceHolder((string) $this->response->getBody())
            );
        }
        Assertions::assertGreaterThanOrEqual(count($etalon), count($actual));
        foreach ($etalon as $key => $needle) {
            Assertions::assertArrayHasKey($key, $actual);
            Assertions::assertEquals($etalon[$key], $actual[$key]);
        }
    }

    /**
     * Prints last response body.
     *
     * @Then print response
     */
    public function printResponse()
    {
        $request = $this->request;
        $response = $this->response;

        echo sprintf(
            "%s %s => %d:\n%s",
            $request->getMethod(),
            (string) ($request instanceof RequestInterface ? $request->getUri() : $request->getUrl()),
            $response->getStatusCode(),
            (string) $response->getBody()
        );
    }

    /**
     * Prepare URL by replacing placeholders and trimming slashes.
     *
     * @param string $url
     *
     * @return string
     */
    protected function prepareUrl($url)
    {
        return ltrim($this->replacePlaceHolder($url), '/');
    }

    /**
     * Sets place holder for replacement.
     *
     * you can specify placeholders, which will
     * be replaced in URL, request or response body.
     *
     * @param string $key   token name
     * @param string $value replace value
     */
    public function setPlaceHolder($key, $value)
    {
        $this->placeHolders[$key] = $value;
    }

    /**
     * Replaces placeholders in provided text.
     *
     * @param string $string
     *
     * @return string
     */
    protected function replacePlaceHolder($string)
    {
        foreach ($this->placeHolders as $key => $val) {
            $string = str_replace($key, $val, $string);
        }

        return $string;
    }

    /**
     * Returns headers, that will be used to send requests.
     *
     * @return array
     */
    protected function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Adds header
     *
     * @param string $name
     * @param string $value
     */
    protected function addHeader($name, $value)
    {
        if (isset($this->headers[$name])) {
            if (!is_array($this->headers[$name])) {
                $this->headers[$name] = array($this->headers[$name]);
            }

            $this->headers[$name][] = $value;
        } else {
            $this->headers[$name] = $value;
        }
    }

    /**
     * Removes a header identified by $headerName
     *
     * @param string $headerName
     */
    protected function removeHeader($headerName)
    {
        if (array_key_exists($headerName, $this->headers)) {
            unset($this->headers[$headerName]);
        }
    }

    protected function sendRequest()
    {
        try {
            $this->response = $this->getClient()->send($this->request);
        } catch (RequestException $e) {
            $this->response = $e->getResponse();

            if (null === $this->response) {
                throw $e;
            }
        }
    }

    protected function getClient()
    {
        if (null === $this->client) {
            throw new \RuntimeException('Client has not been set in WebApiContext');
        }

        return $this->client;
    }
}