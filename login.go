package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/getlantern/systray"
	"github.com/go-toast/toast"
)

var iconData = []byte{
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
	0x18, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// 日志文件
var (
	logFile *os.File
	logger  *log.Logger
	done    chan bool // 全局变量，用于通知主程序退出
)

const (
	_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

var (
	username        = ""
	password        = ""
	getIPAPI        = "http://portal.ucas.ac.cn/cgi-bin/rad_user_info?callback=JQuery"
	initURL         = "https://portal.ucas.ac.cn"
	getChallengeAPI = "https://portal.ucas.ac.cn/cgi-bin/get_challenge"
	srunPortalAPI   = "https://portal.ucas.ac.cn/cgi-bin/srun_portal"
	sleeptime       = 300
	ip              string
	token           string
	i               string
	hmd5            string
	chksum          string
	n               = "200"
	typeVal         = "1"
	acID            = "1"
	enc             = "srun_bx1"
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	isFirstRun      = true // 标记是否首次运行
)

// 初始化日志
func initLogger() {
	// 获取程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		exePath = "."
	}

	logDir := filepath.Dir(exePath)
	logPath := filepath.Join(logDir, "srun_login.log")

	// 打开日志文件
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		// 如果无法创建日志文件，则输出到标准输出
		logger = log.New(os.Stdout, "", log.LstdFlags)
		logger.Println("无法创建日志文件:", err)
		return
	}

	// 创建日志记录器
	logger = log.New(logFile, "", log.LstdFlags)
	logger.Println("=====================")
	logger.Println("认证程序已启动")

	// 如果是首次运行，发送启动通知
	if isFirstRun {
		sendNotification("UCAS网络认证", "认证程序已启动并在后台运行", false)
	}
}

// 发送 Windows 通知
func sendNotification(title, message string, isError bool) {
	notification := toast.Notification{
		AppID:   "UCAS认证程序",
		Title:   title,
		Message: message,
	}

	// 根据是否为错误设置图标
	if isError {
		notification.Icon = filepath.Join(os.Getenv("SystemRoot"), "System32", "imageres.dll,101") // 错误图标
	} else {
		notification.Icon = filepath.Join(os.Getenv("SystemRoot"), "System32", "imageres.dll,77") // 成功图标
	}

	err := notification.Push()
	if err != nil {
		logger.Println("发送通知失败:", err)
	}
}

// 记录日志 (showNotify 决定是否显示通知)
func logMsg(message string, showNotify bool, isError bool) {
	logger.Println(message)

	// 只有在请求显示通知时才发送
	if showNotify {
		title := "UCAS网络认证"
		if isError {
			title += " - 错误"
		}
		sendNotification(title, message, isError)
	}
}

func getBase64(input string) string {
	if input == "" {
		return ""
	}

	var result strings.Builder
	val := 0
	valb := -6

	for _, c := range input {
		val = (val << 8) + int(c)
		valb += 8
		for valb >= 0 {
			result.WriteByte(_ALPHA[(val>>valb)&0x3F])
			valb -= 6
		}
	}

	if valb > -6 {
		result.WriteByte(_ALPHA[((val<<8)>>(valb+8))&0x3F])
	}

	// 添加填充字符
	for result.Len()%4 != 0 {
		result.WriteByte('=')
	}

	return result.String()
}

func getMD5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func ordat(msg string, idx int) int {
	if len(msg) > idx {
		return int(msg[idx])
	}
	return 0
}

func sencode(msg string, key bool) []int {
	l := len(msg)
	pwd := make([]int, 0)

	for i := 0; i < l; i += 4 {
		pwd = append(pwd, ordat(msg, i)|ordat(msg, i+1)<<8|ordat(msg, i+2)<<16|ordat(msg, i+3)<<24)
	}

	if key {
		pwd = append(pwd, l)
	}

	return pwd
}

func lencode(msg []int, key bool) string {
	l := len(msg)
	ll := (l - 1) << 2

	if key {
		m := msg[l-1]
		if m < ll-3 || m > ll {
			return ""
		}
		ll = m
	}

	result := make([]string, l)
	for i := 0; i < l; i++ {
		result[i] = string(msg[i]&0xff) + string((msg[i]>>8)&0xff) + string((msg[i]>>16)&0xff) + string((msg[i]>>24)&0xff)
	}

	if key {
		return strings.Join(result, "")[:ll]
	}
	return strings.Join(result, "")
}

func getXencode(msg, key string) string {
	if msg == "" {
		return ""
	}

	pwd := sencode(msg, true)
	pwdk := sencode(key, false)

	if len(pwdk) < 4 {
		for i := 0; i < 4-len(pwdk); i++ {
			pwdk = append(pwdk, 0)
		}
	}

	n := len(pwd) - 1
	z := pwd[n]
	y := pwd[0]
	c := 0x86014019 | 0x183639A0
	m := 0
	e := 0
	p := 0
	q := int(math.Floor(6 + 52/float64(n+1)))
	d := 0

	for q > 0 {
		d = (d + c) & (0x8CE0D9BF | 0x731F2640)
		e = (d >> 2) & 3

		for p = 0; p < n; p++ {
			y = pwd[p+1]
			m = (z>>5 ^ y<<2) & 0xffffffff
			m = (m + ((y>>3 ^ z<<4) ^ (d ^ y))) & 0xffffffff
			m = (m + (pwdk[(p&3)^e] ^ z)) & 0xffffffff
			pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
			z = pwd[p]
		}

		y = pwd[0]
		m = (z>>5 ^ y<<2) & 0xffffffff
		m = (m + ((y>>3 ^ z<<4) ^ (d ^ y))) & 0xffffffff
		m = (m + (pwdk[(p&3)^e] ^ z)) & 0xffffffff
		pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
		z = pwd[n]
		q--
	}

	return lencode(pwd, false)
}

func getSHA1(value string) string {
	h := sha1.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func getChksum() string {
	chkstr := token + username
	chkstr += token + hmd5
	chkstr += token + acID
	chkstr += token + ip
	chkstr += token + n
	chkstr += token + typeVal
	chkstr += token + i
	return chkstr
}

func getInfo() string {
	infoTemp := map[string]string{
		"username": username,
		"password": password,
		"ip":       ip,
		"acid":     acID,
		"enc_ver":  enc,
	}

	jsonData, _ := json.Marshal(infoTemp)
	return string(jsonData)
}

func initGetIP() string {
	client := &http.Client{}
	resp, err := client.Get(getIPAPI)
	if err != nil {
		// 获取IP失败时才显示通知
		logMsg(fmt.Sprintf("获取IP失败: %v", err), true, true)
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// 去掉 jQuery( 和 )
	bodyStr := string(body)
	jsonStr := bodyStr[7 : len(bodyStr)-1]

	var data map[string]interface{}
	json.Unmarshal([]byte(jsonStr), &data)

	clientIP, ok1 := data["client_ip"].(string)
	onlineIP, ok2 := data["online_ip"].(string)

	if ok1 {
		ip = clientIP
	} else if ok2 {
		ip = onlineIP
	}

	logMsg(fmt.Sprintf("IP: %s", ip), false, false)
	return ip
}

func getToken() {
	client := &http.Client{}
	params := url.Values{}
	params.Add("callback", "jQuery112404953340710317169_"+strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))
	params.Add("username", username)
	params.Add("ip", ip)
	params.Add("_", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))

	req, _ := http.NewRequest("GET", getChallengeAPI+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		// 获取token失败时才显示通知
		logMsg(fmt.Sprintf("获取Token失败: %v", err), true, true)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 使用正则表达式提取 token
	re := regexp.MustCompile(`"challenge":"(.*?)"`)
	matches := re.FindStringSubmatch(bodyStr)
	if len(matches) > 1 {
		token = matches[1]
		logMsg(bodyStr, false, false)
		logMsg(fmt.Sprintf("Token为: %s", token), false, false)
	} else {
		// 解析失败时才显示通知
		logMsg("解析Token失败", true, true)
	}
}

func isConnected() bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	_, err := client.Get("https://www.baidu.com")
	return err == nil
}

func doComplexWork() {
	i = getInfo()
	i = "{SRBX1}" + getBase64(getXencode(i, token))
	hmd5 = getMD5(password, token)
	chksum = getSHA1(getChksum())
	logMsg("所有加密工作已完成", false, false)
}

func login() bool {
	client := &http.Client{}
	params := url.Values{}
	params.Add("callback", "jQuery11240645308969735664_"+strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))
	params.Add("action", "login")
	params.Add("username", username)
	params.Add("password", "{MD5}"+hmd5)
	params.Add("ac_id", acID)
	params.Add("ip", ip)
	params.Add("chksum", chksum)
	params.Add("info", i)
	params.Add("n", n)
	params.Add("type", typeVal)
	params.Add("os", "windows+10")
	params.Add("name", "windows")
	params.Add("double_stack", "0")
	params.Add("_", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))

	req, _ := http.NewRequest("GET", srunPortalAPI+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		// 登录请求失败时才显示通知
		logMsg(fmt.Sprintf("登录请求失败: %v", err), true, true)
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	response := string(body)
	logMsg(response, false, false)

	// 检查登录是否成功
	if strings.Contains(response, "\"res\":\"ok\"") {
		logMsg("登录成功！", isFirstRun, false) // 仅首次运行才显示成功通知
		return true
	} else if strings.Contains(response, "\"error\":") {
		// 提取错误信息
		re := regexp.MustCompile(`"error":"(.*?)"`)
		matches := re.FindStringSubmatch(response)
		if len(matches) > 1 {
			// 登录失败总是显示通知
			logMsg(fmt.Sprintf("登录失败: %s", matches[1]), true, true)
		} else {
			logMsg("登录失败，未知错误", true, true)
		}
		return false
	}

	return false
}

func loadEnvVars() {
	if username == "" {
		username = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if password == "" {
		password = strings.TrimSpace(os.Getenv("PASSWORD"))
	}
	if initURL == "" {
		initURL = strings.TrimSpace(os.Getenv("init_url"))
	}
	if getChallengeAPI == "" {
		getChallengeAPI = strings.TrimSpace(os.Getenv("get_challenge_api"))
	}
	if srunPortalAPI == "" {
		srunPortalAPI = strings.TrimSpace(os.Getenv("srun_portal_api"))
	}
	if getIPAPI == "" {
		getIPAPI = strings.TrimSpace(os.Getenv("get_ip_api"))
	}
}

func checkAndLogin() {
	if isConnected() {
		// 已连接时不显示通知
		logMsg("已通过认证，无需再次认证", false, false)
		return
	} else {
		// 需要认证时，只记录不通知
		logMsg("网络未认证，开始认证过程", false, false)
		ip = initGetIP()
		if ip == "" {
			return // 如果获取IP失败，已经通知过了
		}

		getToken()
		if token == "" {
			return // 如果获取token失败，已经通知过了
		}

		doComplexWork()
		login() // login函数已经处理了通知逻辑
	}
}

// 初始化系统托盘图标
func initSystray() {
	// 在一个新的 goroutine 中启动系统托盘
	go systray.Run(onReady, onExit)
}

// 系统托盘准备就绪时的回调函数
func onReady() {
	// 设置图标（使用示例图标，你可以替换为自己的图标）
	systray.SetIcon(iconData)
	systray.SetTitle("UCAS认证程序")
	systray.SetTooltip("UCAS校园网认证程序")

	// 添加菜单项
	mLogin := systray.AddMenuItem("立即认证", "立即执行网络认证")
	mStatus := systray.AddMenuItem("检查状态", "检查当前网络认证状态")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("退出", "退出程序")

	// 处理菜单点击事件
	go func() {
		for {
			select {
			case <-mLogin.ClickedCh:
				// 用户点击"立即认证"
				logMsg("用户触发立即认证", false, false)
				go func() {
					checkAndLogin()
					// 认证后更新状态
					if isConnected() {
						mStatus.SetTitle("状态: 已连接")
						sendNotification("UCAS网络认证", "认证成功", false)
					} else {
						mStatus.SetTitle("状态: 未连接")
						sendNotification("UCAS网络认证", "认证失败", true)
					}
				}()

			case <-mStatus.ClickedCh:
				// 用户点击"检查状态"
				go func() {
					if isConnected() {
						mStatus.SetTitle("状态: 已连接")
						sendNotification("UCAS网络认证", "当前已连接到网络", false)
					} else {
						mStatus.SetTitle("状态: 未连接")
						sendNotification("UCAS网络认证", "当前未连接到网络", true)
					}
				}()

			case <-mQuit.ClickedCh:
				// 用户点击"退出"
				logMsg("用户通过托盘菜单退出程序", false, false)
				systray.Quit()
				return
			}
		}
	}()

	// 初始检查状态
	if isConnected() {
		mStatus.SetTitle("状态: 已连接")
	} else {
		mStatus.SetTitle("状态: 未连接")
	}

	logMsg("系统托盘图标已初始化", false, false)
}

// 系统托盘退出时的回调函数
func onExit() {
	logMsg("系统托盘已退出", false, false)
	// 通知主程序退出
	done <- true
}

func main() {
	// 初始化日志
	initLogger()
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	// 加载配置
	config := LoadConfig()

	// 使用配置文件中的值更新全局变量
	if config.Username != "" {
		username = config.Username
	}
	if config.Password != "" {
		password = config.Password
	}
	if config.Interval > 0 {
		sleeptime = config.Interval
	}

	// 加载环境变量作为备用
	loadEnvVars()

	// 检查用户名和密码是否设置
	if username == "" || password == "" {
		msg := "用户名或密码未设置，请在config.json文件中配置或设置环境变量"
		logMsg(msg, true, true)
		time.Sleep(10 * time.Second) // 等待用户看到通知
		return
	}

	// 处理系统信号，优雅退出
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done = make(chan bool, 1) // 注意: 将 done 改为全局变量

	// 启动信号处理
	go func() {
		<-sigs
		logMsg("程序收到退出信号，即将退出", false, false)
		systray.Quit() // 退出系统托盘
		done <- true
	}()

	// 初始化系统托盘
	initSystray()

	// 首次运行
	checkAndLogin()
	isFirstRun = false // 标记非首次运行

	// 主循环
	ticker := time.NewTicker(time.Duration(sleeptime) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			checkAndLogin()
		case <-done:
			logMsg("程序正常退出", false, false)
			return
		}
	}
}
