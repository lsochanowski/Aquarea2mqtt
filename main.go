package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var AquareaServiceCloudURL string = "https://aquarea-service.panasonic.com/"
var AquareaSmartCloudURL string = "https://aquarea-smart.panasonic.com/"

var Shiesuahruefutohkun string

type ExtractedData struct {
	EnduserID                         string
	RunningStatus                     string
	WorkingMode                       string
	WaterInleet                       string
	WaterOutleet                      string
	Zone1ActualAirTemperature         string
	Zone1SetpointAirTemperature       string
	Zone1WaterTemperature             string
	Zone2ActualAirTemperature         string
	Zone2SetpointAirTemperature       string
	Zone2WaterTemperature             string
	DailyWaterTankActualTemperature   string
	DailyWaterTankSetpointTemperature string
	BufferTankTemperature             string
	OutdoorTemperature                string
	CompressorStatus                  string
	WaterFlow                         string
	PumpSpeed                         string
	HeatDirection                     string
	RoomHeaterStatus                  string
	DailyWaterHeaterStatus            string
	DefrostStatus                     string
	SolarStatus                       string
	SolarTemperature                  string
	BiMode                            string
	ErrorStatus                       string
	CompressorFrequency               string
	Runtime                           string
	RunCount                          string
	RoomHeaterPerformance             string
	RoomHeaterRunTime                 string
	DailyWaterHeaterRunTime           string
}

func main() {
	cookieJar, _ := cookiejar.New(nil)
	var cookies []*http.Cookie
	cookies = append(cookies, &http.Cookie{Name: "operationDeviceTop", Value: "1"})
	curl, _ := url.Parse("https://aquarea-smart.panasonic.com")
	cookieJar.SetCookies(curl, cookies)

	client := http.Client{
		Jar:     cookieJar,
		Timeout: AquateaTimeout,
	}
	MC, MT := MakeMQTTConn()
	err := GetFirstShiesuahruefutohkun(client)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = GetLogin(client)
	if err != nil {
		fmt.Println(err)

		return
	}
	err, EU, aqdict := GetInstallerHome(client)
	if err != nil {
		fmt.Println(err)

		return
	}
	for {

		if err == nil {
			for _, SelectedEndUser := range EU {
				e, U := ParseAQData(SelectedEndUser, client, aqdict)
				if e != nil {
					fmt.Println(e)
					break

				}
				//fmt.Println(U)
				fmt.Printf("%s - ", U)
				md5 := md5.Sum([]byte(fmt.Sprintf("%s", U)))
				fmt.Printf("%x\n", md5)
				fmt.Println("\n\n", cookieJar, "\n\n")

				TestSetRedirect(client, SelectedEndUser)
				fmt.Println("\n\n", cookieJar, "\n\n")

				if md5 != LastChecksum {
					PublishStates(MC, MT, U)
					LastChecksum = md5
				} else {
					fmt.Printf("Same Checksum SKIPING\n")

				}
			}
		} else {
			fmt.Println(err)
		}
		time.Sleep(2 * time.Second)

	}

}

func TestSetRedirect(client http.Client, eu Enduser) {

	resp, err := client.Get(AquareaServiceCloudURL + "enduser/confirmStep1Policy")

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

	LoginURL := AquareaServiceCloudURL + "/enduser/api/request/create/sso"
	resp, err = client.PostForm(LoginURL, url.Values{
		"var.gwUid":           {eu.GwUID},
		"shiesuahruefutohkun": {Shiesuahruefutohkun},
	})
	if err != nil {
		fmt.Println(err)
		return

	}
	body, err = ioutil.ReadAll(resp.Body)
	var AQCSR AquareaServiceCloudSSOReponse
	err = json.Unmarshal(body, &AQCSR)
	if err != nil {
		return

	}
	resp.Body.Close()
	fmt.Println(AQCSR.SsoKey, eu.DeviceID, eu.Gwid)

	LoginURL = "https://aquarea-smart.panasonic.com/remote/v1/api/auth/sso"
	resp, err = client.PostForm(LoginURL, url.Values{
		"var.ssoKey": {AQCSR.SsoKey},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	body2, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body2))

	url := "https://aquarea-smart.panasonic.com/remote/v1/api/devices/008007B767718332001434545313831373030634345373130434345373138313931304300000000"
	fmt.Println("URL:>", url)

	var jsonStr = []byte(`{"status":[{"deviceGuid":"008007B767718332001434545313831373030634345373130434345373138313931304300000000","zoneStatus":[{"zoneId":1,"heatSet":25}]}]}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ = ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))

}

// func ProcASC() {
// 	url := "https://aquarea-smart.panasonic.com/remote/v1/api/auth/sso"
// 	req, err := http.NewRequest("POST", url, nil)
// 	if err != nil {
// 			return
// 	}

// 	req.AddCookie(&http.Cookie{Name: "ds_user_id", Value: ds_user_id})
// 	req.AddCookie(&http.Cookie{Name: "sessionid", Value: sessionid})
// 	req.AddCookie(&http.Cookie{Name: "csrftoken", Value: csrftoken})

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 			return
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != 200 {
// 			err = errors.New(url +
// 					"\nresp.StatusCode: " + strconv.Itoa(resp.StatusCode))
// 			return
// 	}

// 	return ioutil.ReadAll(resp.Body)
// }

type AquareaServiceCloudSSOReponse struct {
	SsoKey    string `json:"ssoKey"`
	ErrorCode int    `json:"errorCode"`
}

func MakeMQTTConn() (mqtt.Client, mqtt.Token) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("%s://%s:%s", "tcp", MqttServer, MqttPort))
	opts.SetPassword(MqttPass)
	opts.SetUsername(MqttLogin)
	opts.SetClientID(MqttClientID)

	opts.SetKeepAlive(MqttKeepalive)
	opts.SetOnConnectHandler(startsub)
	opts.SetConnectionLostHandler(connLostHandler)

	// connect to broker
	client := mqtt.NewClient(opts)
	//defer client.Disconnect(uint(2))

	token := client.Connect()
	if token.Wait() && token.Error() != nil {
		fmt.Printf("Fail to connect broker, %v", token.Error())
	}
	return client, token

}

func connLostHandler(c mqtt.Client, err error) {
	fmt.Printf("Connection lost, reason: %v\n", err)

	//Perform additional action...
}

func startsub(c mqtt.Client) {
	//c.Subscribe("jablotron/+/+/set", 2, HandleMSGfromMQTT)

	//Perform additional action...
}

func PublishStates(client mqtt.Client, token mqtt.Token, U ExtractedData) {

	//literate over struc't a i can't belive there is no better way to do it....
	jsonData, err := json.Marshal(U)
	if err != nil {
		fmt.Println("BLAD:", err)
		return
	}
	var m map[string]string
	err = json.Unmarshal([]byte(jsonData), &m)
	if err != nil {
		fmt.Println("BLAD:", err)
		return
	}

	for key, value := range m {
		//	fmt.Println("\n", "Key:", key, "Value:", value, "\n")
		TOP := "aquarea/state/" + fmt.Sprintf("%s/%s", m["EnduserID"], key)
		//	fmt.Println("Publikuje do ", TOP, "warosc", value)
		value = strings.TrimSpace(value)

		token = client.Publish(TOP, byte(0), false, value)
		if token.Wait() && token.Error() != nil {
			fmt.Printf("Fail to publish, %v", token.Error())
		}
	}

}

func ParseAQData(SelectedEndUser Enduser, client http.Client, aqdict map[string]string) (error, ExtractedData) {
	var ED ExtractedData
	err := GetUIShiesuahruefutohkun(client, SelectedEndUser)
	err, r := GetDeviceInformation(client, SelectedEndUser)
	ED.EnduserID = SelectedEndUser.Gwid
	ED.RunningStatus = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText005.TextValue)
	ED.WorkingMode = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText007.TextValue)
	ED.WaterInleet = r.StatusDataInfo.FunctionStatusText009.Value
	ED.WaterOutleet = r.StatusDataInfo.FunctionStatusText011.Value
	ED.Zone1ActualAirTemperature = r.StatusDataInfo.FunctionStatusText013.Value
	ED.Zone1SetpointAirTemperature = r.StatusDataInfo.FunctionStatusText015.Value
	ED.Zone1WaterTemperature = r.StatusDataInfo.FunctionStatusText017.Value
	ED.Zone2ActualAirTemperature = r.StatusDataInfo.FunctionStatusText019.Value
	ED.Zone2SetpointAirTemperature = r.StatusDataInfo.FunctionStatusText021.Value
	ED.Zone2WaterTemperature = r.StatusDataInfo.FunctionStatusText023.Value
	ED.DailyWaterTankActualTemperature = r.StatusDataInfo.FunctionStatusText025.Value
	ED.DailyWaterTankSetpointTemperature = r.StatusDataInfo.FunctionStatusText027.Value
	ED.BufferTankTemperature = r.StatusDataInfo.FunctionStatusText029.Value
	ED.OutdoorTemperature = r.StatusDataInfo.FunctionStatusText031.Value
	ED.CompressorStatus = "TODO__GDZIES MUSI BYC__/33 "
	ED.WaterFlow = r.StatusDataInfo.FunctionStatusText035.Value
	ED.PumpSpeed = r.StatusDataInfo.FunctionStatusText037.Value
	ED.HeatDirection = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText039.TextValue)
	ED.RoomHeaterStatus = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText041.TextValue)
	ED.DailyWaterHeaterStatus = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText043.TextValue)
	ED.DefrostStatus = TranslateCodeToString(client, r.StatusDataInfo.FunctionStatusText045.TextValue)
	ED.SolarStatus = r.StatusDataInfo.FunctionStatusText047.Value
	ED.SolarTemperature = r.StatusDataInfo.FunctionStatusText049.Value
	ED.BiMode = r.StatusDataInfo.FunctionStatusText051.Value
	ED.ErrorStatus = r.StatusDataInfo.FunctionStatusText053.Value
	ED.CompressorFrequency = r.StatusDataInfo.FunctionStatusText056.Value
	ED.Runtime = r.StatusDataInfo.FunctionStatusText058.Value
	ED.RunCount = r.StatusDataInfo.FunctionStatusText060.Value
	ED.RoomHeaterPerformance = r.StatusDataInfo.FunctionStatusText063.Value
	ED.RoomHeaterRunTime = r.StatusDataInfo.FunctionStatusText065.Value
	ED.DailyWaterHeaterRunTime = r.StatusDataInfo.FunctionStatusText068.Value
	return err, ED
}

func TranslateCodeToString(client http.Client, source string) string {
	// todo switch to download it everytime from aquarea
	aqdict := "{\"2006-01C0\":\"set\",\"2006-09C0\":\"Off\",\"2000-0045\":\"Unknown\",\"2006-0D00\":\"Room heater\",\"2000-0321\":\"IDU\",\"2000-0c09\":\"French\",\"2000-0c08\":\"Finnish\",\"2000-0c07\":\"Estonian\",\"2000-0c06\":\"English\",\"2000-0041\":\"Now processing…\",\"2000-0042\":\"Now processing…\",\"2006-09B0\":\"On\",\"2000-0c01\":\"Bulgarian\",\"2999-0094\":\"Terms of use\",\"2000-0c05\":\"Deutsch\",\"2006-0640\":\"Room heater\",\"2000-0c04\":\"Danish\",\"2999-0098\":\"Privacy Notice\",\"2000-0c03\":\"Czech\",\"2000-0c02\":\"Croatian\",\"2006-0120\":\"Mode\",\"2006-0910\":\"On\",\"2000-0311\":\"ID\",\"2006-0E10\":\"Operating time\",\"2006-01B0\":\"DHW tank\",\"2000-0391\":\"Monitoring + control\",\"2006-0190\":\"set\",\"2006-09A0\":\"Off\",\"2999-009b\":\"Cookie Policy\",\"2000-0031\":\"Set\",\"2006-0630\":\"3-way valve\",\"2006-0110\":\"Operation\",\"2006-0990\":\"On\",\"2006-0900\":\"Off\",\"2006-0348\":\"Auto (Cool) + Tank\",\"2999-00e0\":\"Logout\",\"2006-0E00\":\"Tank heater\",\"2000-0100\":\"Log out?\",\"2000-0221\":\"Status\",\"2006-0A00\":\"On\",\"2006-01A0\":\"water\",\"2000-0b09\":\"Spain\",\"2000-0b08\":\"Estonia\",\"2999-0038\":\"Registration\",\"2000-0060\":\"No user\",\"2000-0b07\":\"Denmark\",\"2000-0065\":\"AQUAREA Smart Cloud\",\"2000-0341\":\"Approved Full access Until\",\"2006-0180\":\"Zone2 temp.\",\"2000-0b02\":\"Belgium\",\"2000-0b01\":\"Austria\",\"2006-0620\":\"Pump speed\",\"2999-0030\":\"Customer\",\"2000-0b06\":\"Germany\",\"2006-0343\":\"Auto (Heat) + Tank\",\"2000-0b05\":\"Czech Republic\",\"2006-0100\":\"System status\",\"2006-0980\":\"Off\",\"2000-0b04\":\"Switzerland\",\"2999-0034\":\"List\",\"2000-0b03\":\"Bulgaria\",\"2000-0c0f\":\"Dutch\",\"2006-0339\":\"Heat + Tank\",\"2000-0c0a\":\"Hungarian\",\"2006-033E\":\"Cool + Tank\",\"2000-0331\":\"ODU\",\"2000-0211\":\"User information\",\"2000-0c0e\":\"Lithuanian\",\"2999-003b\":\"Delete\",\"2000-0c0d\":\"Latvian\",\"2000-0c0c\":\"Italian\",\"2006-0C30\":\"Number of operations\",\"2000-0c0b\":\"Irish\",\"2000-0050\":\"AQUAREA Service Cloud\",\"2000-0c19\":\"Greek\",\"2006-0690\":\"Bivalent\",\"2000-0c18\":\"Turkish\",\"2000-0c17\":\"Swedish\",\"2006-0170\":\"water\",\"2000-0055\":\"AQUAREA Service Cloud\",\"2006-032F\":\"Auto (Heat)\",\"2000-0c12\":\"Portuguese\",\"2000-0c11\":\"Polish\",\"2006-0610\":\"Water flow\",\"2000-0c10\":\"Norwegian\",\"2006-0334\":\"Auto (Cool)\",\"2000-0c16\":\"Spanish\",\"2006-0970\":\"On\",\"2000-0c15\":\"Slovenian\",\"2000-0c14\":\"Slovak\",\"2000-0c13\":\"Romanian\",\"2000-0125\":\"The device has been deleted.\",\"2000-0b1b\":\"Turkey\",\"2006-06A0\":\"Error\",\"2000-0001\":\"Cancel\",\"2000-0b1a\":\"Finland\",\"2006-032A\":\"Cool\",\"2006-0C20\":\"Operating time\",\"2000-0401\":\"Full access\",\"2000-0005\":\"OK\",\"2006-0680\":\"Solar temp.\",\"2006-0160\":\"set\",\"2000-0120\":\"Delete this device from this service?\",\"2000-0241\":\"Data log\",\"2000-0361\":\"Access rights\",\"2006-0600\":\"Thermo\",\"2006-0325\":\"Heat\",\"2000-0a01\":\"Off\",\"2006-0960\":\"Off\",\"2006-0320\":\"Tank\",\"2000-0a05\":\"On\",\"2000-0b0b\":\"United Kingdom\",\"2000-0b0a\":\"France\",\"2006-09F0\":\"Off\",\"2000-0b0f\":\"Italy\",\"2006-0C10\":\"Compressor frequency\",\"2000-0b0e\":\"Ireland\",\"2000-0b0d\":\"Hungary\",\"2000-0b0c\":\"Croatia\",\"2000-0070\":\"AQUAREA Smart Cloud\",\"2000-0b19\":\"Slovakia\",\"2006-0150\":\"Zone1 temp.\",\"2000-0b18\":\"Slovenia\",\"2000-0351\":\"Waiting for approval\",\"2000-0110\":\"Return to login page?\",\"2000-0231\":\"Statistics\",\"2999-0060\":\"Company\",\"2000-0b13\":\"Norway\",\"2000-0b12\":\"Netherlands\",\"2000-0b11\":\"Latvia\",\"2006-0950\":\"Tank\",\"2000-0b10\":\"Lithuania\",\"2000-0b17\":\"Sweden\",\"2006-0310\":\"On\",\"2000-0b16\":\"Romania\",\"2000-0b15\":\"Portugal\",\"2000-0b14\":\"Poland\",\"2006-0670\":\"Solar\",\"2006-01E0\":\"Outdoor temp.\",\"2000-0a1c\":\"Dec\",\"2000-0a1b\":\"Nov\",\"2000-0a1a\":\"Oct\",\"2006-0C00\":\"Compressor\",\"2006-0D20\":\"Operating time\",\"2000-0381\":\"Monitoring only\",\"2006-0140\":\"Outlet water\",\"2000-0021\":\"Send\",\"2006-0940\":\"Room\",\"2006-0300\":\"Off\",\"2000-012f\":\"Device ID\",\"2006-0660\":\"Defrost\",\"2006-01D0\":\"Buffer tank\",\"2999-0090\":\"Agreement\",\"2000-012a\":\"Customer name\",\"2000-0015\":\"Agree\",\"2006-09D0\":\"On\",\"2006-0D10\":\"Heater capacity\",\"2999-00b0\":\"Help\",\"2006-0130\":\"Inlet water\",\"2000-0a19\":\"Sep\",\"2000-0011\":\"Disagree\",\"2000-0371\":\"On request\",\"2000-0251\":\"Setting\",\"2000-0a14\":\"Apr\",\"2000-0a13\":\"Mar\",\"2000-0a12\":\"Feb\",\"2000-0a11\":\"Jan\",\"2000-0a18\":\"Aug\",\"2000-0a17\":\"Jul\",\"2006-0650\":\"Tank heater\",\"2999-0000\":\"Menu\",\"2000-0a16\":\"Jun\",\"2000-0a15\":\"May\"}"
	var m map[string]string

	//	client := http.Client{
	//		Jar: cookieJar,
	//	}
	//	resp, err := client.Get(AquareaServiceCloudURL + "installer/functionStatus")
	//	if err != nil {
	//		return source
	//	}
	//	defer resp.Body.Close()
	//	body, err := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(body))
	//	re33, err := regexp.Compile(`const jsonMessage = eval\('\((.+)\)'`)
	//	ss33 := re33.FindAllStringSubmatch(string(body), -1)
	//	if len(ss33) > 0 {

	//result := strings.Replace(ss33[0], "\\", "", -1)
	//		fmt.Println(ss33[0][0])
	//

	//	}
	//	fmt.Println(m)

	err := json.Unmarshal([]byte(aqdict), &m)
	if err != nil {
		fmt.Println("BLAD:", err)
		return source
	}
	if _, found := m[source]; !found {
		return source
	}
	return m[source]
}

func GetFirstShiesuahruefutohkun(client http.Client) error {

	resp, err := client.Get(AquareaServiceCloudURL)
	if err != nil {
		return err

	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	re, err := regexp.Compile(`const shiesuahruefutohkun = '(.+)'`)
	ss := re.FindStringSubmatch(string(body))
	if len(ss) > 0 {
		Shiesuahruefutohkun = ss[1]

	} else {
		return err

	}
	if err != nil {
		return err

	}

	return nil

}

func GetUIShiesuahruefutohkun(client http.Client, eu Enduser) error {

	LoginURL := AquareaServiceCloudURL + "/installer/functionUserInformation"
	resp, err := client.PostForm(LoginURL, url.Values{
		"var.functionSelectedGwUid": {eu.GwUID},
	})
	if err != nil {
		return err

	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err

	}
	resp.Body.Close()

	re, err := regexp.Compile(`const shiesuahruefutohkun = '(.+)'`)
	ss := re.FindStringSubmatch(string(body))
	if len(ss) > 0 {
		Shiesuahruefutohkun = ss[1]

	} else {
		return err

	}
	if err != nil {
		return err

	}
	return nil

}

func GetLogin(client http.Client) error {

	var Response LogResponse
	LoginURL := AquareaServiceCloudURL + "/installer/api/auth/login"
	data := []byte(AquareaServiceCloudLogin + AquareaServiceCloudPassword)
	resp, err := client.PostForm(LoginURL, url.Values{
		"var.loginId":         {AquareaServiceCloudLogin},
		"var.password":        {fmt.Sprintf("%x", md5.Sum(data))},
		"var.inputOmit":       {"false"},
		"shiesuahruefutohkun": {Shiesuahruefutohkun},
	})
	if err != nil {
		fmt.Println(err)
		return err

	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return err

	}
	defer resp.Body.Close()

	err = json.Unmarshal(b, &Response)
	if len(Response.Message) > 0 {
		if Response.Message[0].ErrorCode != "0" {
			err = errors.New(Response.Message[0].ErrorMessage)

		}
	}

	if err != nil {
		fmt.Println(err)
		return err

	}
	return nil
}

func GetInstallerHome(client http.Client) (error, []Enduser, map[string]string) {

	var EndUsersList EndUsersList
	var EndUsers []Enduser
	var err error
	var m map[string]string

	var Shiesuahruefutohkun string
	resp, err := client.Get(AquareaServiceCloudURL + "installer/home")
	if err != nil {
		return err, EndUsers, m

	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	re, err := regexp.Compile(`const shiesuahruefutohkun = '(.+)'`)
	ss := re.FindStringSubmatch(string(body))

	re33, err := regexp.Compile(`const jsonMessage = eval\('\((.+)\)'`)
	ss33 := re33.FindStringSubmatch(string(body))
	if len(ss33) > 0 {

		result := strings.Replace(ss33[1], "\\", "", -1)
		err = json.Unmarshal([]byte(result), &m)

	}

	if len(ss) > 0 {
		Shiesuahruefutohkun = ss[1]
	} else {
		err = errors.New("BLAD")
	}
	resp.Body.Close()

	LoginURL := AquareaServiceCloudURL + "/installer/api/endusers"
	resp, err = client.PostForm(LoginURL, url.Values{
		"var.name":            {""},
		"var.deviceId":        {""},
		"var.idu":             {""},
		"var.odu":             {""},
		"var.sortItem":        {"userName"},
		"var.sortOrder":       {"0"},
		"var.offset":          {"0"},
		"var.limit":           {"999"},
		"var.mapSizeX":        {"0"},
		"var.mapSizeY":        {"0"},
		"var.readNew":         {"1"},
		"shiesuahruefutohkun": {Shiesuahruefutohkun},
	})
	b, err := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(b, &EndUsersList)

	EndUsers = EndUsersList.Endusers

	resp.Body.Close()

	if err != nil {
		return err, EndUsers, m

	}
	return nil, EndUsers, m

}

func GetDeviceInformation(client http.Client, eu Enduser) (error, AquareaStatusResponse) {

	var AquareaStatusResponse AquareaStatusResponse

	LoginURL := AquareaServiceCloudURL + "/installer/api/function/status"
	resp, err := client.PostForm(LoginURL, url.Values{
		"var.deviceId":        {eu.DeviceID},
		"shiesuahruefutohkun": {Shiesuahruefutohkun},
	})
	if err != nil {
		return err, AquareaStatusResponse

	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err, AquareaStatusResponse

	}
	SB := string(b)
	//fmt.Println("\n")
	//fmt.Println(SB)
	//fmt.Println("\n")
	err = json.Unmarshal([]byte(SB), &AquareaStatusResponse)

	//fmt.Println(AquareaStatusResponse.StatusDataInfo.FunctionStatusText027.Value)
	resp.Body.Close()

	if err != nil {
		return err, AquareaStatusResponse

	}
	return nil, AquareaStatusResponse
}

type EndUsersList struct {
	ZoomMap            int       `json:"zoomMap"`
	ErrorCode          int       `json:"errorCode"`
	Endusers           []Enduser `json:"endusers"`
	LongitudeCenterMap string    `json:"longitudeCenterMap"`
	Size               int       `json:"size"`
	LatitudeCenterMap  string    `json:"latitudeCenterMap"`
}
type Enduser struct {
	Address    string      `json:"address"`
	CompanyID  string      `json:"companyId"`
	Connection string      `json:"connection"`
	DeviceID   string      `json:"deviceId"`
	EnduserID  string      `json:"enduserId"`
	ErrorCode  interface{} `json:"errorCode"`
	ErrorName  string      `json:"errorName"`
	GwUID      string      `json:"gwUid"`
	Gwid       string      `json:"gwid"`
	Idu        string      `json:"idu"`
	Latitude   string      `json:"latitude"`
	Longitude  string      `json:"longitude"`
	Name       string      `json:"name"`
	Odu        string      `json:"odu"`
	Power      string      `json:"power"`
}

type AquareaStatusResponse struct {
	ErrorCode      int `json:"errorCode"`
	StatusDataInfo struct {
		FunctionStatusText005 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-005"`
		FunctionStatusText027 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-027"`
		FunctionStatusText049 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-049"`
		FunctionStatusText025 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-025"`
		FunctionStatusText047 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-047"`
		FunctionStatusText068 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-068"`
		FunctionStatusText009 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-009"`
		FunctionStatusText007 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-007"`
		FunctionStatusText029 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-029"`
		FunctionStatusText041 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-041"`
		FunctionStatusText063 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-063"`
		FunctionStatusText060 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-060"`
		FunctionStatusText023 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-023"`
		FunctionStatusText045 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-045"`
		FunctionStatusText021 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-021"`
		FunctionStatusText043 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-043"`
		FunctionStatusText065 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-065"`
		FunctionStatusText015 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-015"`
		FunctionStatusText037 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-037"`
		FunctionStatusText058 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-058"`
		FunctionStatusText013 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-013"`
		FunctionStatusText035 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-035"`
		FunctionStatusText019 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-019"`
		FunctionStatusText017 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-017"`
		FunctionStatusText039 struct {
			TextValue string `json:"textValue"`
			Type      string `json:"type"`
		} `json:"function-status-text-039"`
		FunctionStatusText051 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-051"`
		FunctionStatusText056 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-056"`
		FunctionStatusText011 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-011"`
		FunctionStatusText031 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-031"`
		FunctionStatusText053 struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"function-status-text-053"`
	} `json:"statusDataInfo"`
	StatusBackgroundDataInfo struct {
		ZeroXA0 struct {
			Value string `json:"value"`
		} `json:"0xA0"`
		ZeroX20 struct {
			Value string `json:"value"`
		} `json:"0x20"`
		ZeroXE1 struct {
			Value string `json:"value"`
		} `json:"0xE1"`
		ZeroXE0 struct {
			Value string `json:"value"`
		} `json:"0xE0"`
		ZeroXFA struct {
			Value string `json:"value"`
		} `json:"0xFA"`
		ZeroXF0 struct {
			Value string `json:"value"`
		} `json:"0xF0"`
		ZeroX80 struct {
			Value string `json:"value"`
		} `json:"0x80"`
		ZeroXF9 struct {
			Value string `json:"value"`
		} `json:"0xF9"`
		ZeroXC4 struct {
			Value string `json:"value"`
		} `json:"0xC4"`
	} `json:"statusBackgroundDataInfo"`
}

type LogResponse struct {
	ErrorCode int `json:"errorCode"`
	Message   []struct {
		ErrorMessage string `json:"errorMessage"`
		ErrorCode    string `json:"errorCode"`
	} `json:"message"`
}
