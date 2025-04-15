package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config 存储应用配置
type Config struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Interval int    `json:"interval"`
}

// LoadConfig 从配置文件加载配置
func LoadConfig() *Config {
	// 默认配置
	config := &Config{
		Username: "",
		Password: "",
		Interval: 300,
	}

	// 获取程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		logMsg("无法获取程序路径，使用默认配置", true, true)
		return config
	}

	// 配置文件路径
	configPath := filepath.Join(filepath.Dir(exePath), "config.json")

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 创建示例配置文件
		exampleConfig := &Config{
			Username: "your_username@mails.ucas.ac.cn",
			Password: "your_password",
			Interval: 300,
		}

		configData, _ := json.MarshalIndent(exampleConfig, "", "  ")
		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			logMsg("创建配置文件模板失败: "+err.Error(), true, true)
		} else {
			logMsg("已创建配置文件模板: "+configPath, true, true)
		}

		return config
	}

	// 读取配置文件
	configData, err := os.ReadFile(configPath)
	if err != nil {
		logMsg("读取配置文件失败: "+err.Error(), true, true)
		return config
	}

	// 解析配置
	if err := json.Unmarshal(configData, config); err != nil {
		logMsg("解析配置文件失败: "+err.Error(), true, true)
		return config
	}

	return config
}
