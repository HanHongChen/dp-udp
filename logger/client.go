package logger

import (
	"github.com/HanHongChen/dp-udp/constant"
	loggergo "github.com/Alonza0314/logger-go/v2"
	loggergoModel "github.com/Alonza0314/logger-go/v2/model"
	loggergoUtil "github.com/Alonza0314/logger-go/v2/util"
)

type ClientLogger struct {
	*loggergo.Logger

	CfgLog    loggergoModel.LoggerInterface
	ClientLog loggergoModel.LoggerInterface
	Udp1Log   loggergoModel.LoggerInterface
	Udp2Log   loggergoModel.LoggerInterface
	TunLog    loggergoModel.LoggerInterface
}

func NewClientLogger(level loggergoUtil.LogLevelString, filePath string, debugMode bool) *ClientLogger {
	logger := loggergo.NewLogger(filePath, debugMode)
	logger.SetLevel(level)

	return &ClientLogger{
		Logger:    logger,
		CfgLog:    logger.WithTags(constant.CLIENT_TAG, constant.CONFIG_TAG),
		ClientLog: logger.WithTags(constant.CLIENT_TAG, constant.CLIENT_TAG),
		Udp1Log:   logger.WithTags(constant.CLIENT_TAG, constant.UDP_1_TAG),
		Udp2Log:   logger.WithTags(constant.CLIENT_TAG, constant.UDP_2_TAG),
		TunLog:    logger.WithTags(constant.CLIENT_TAG, constant.TUN_TAG),
	}
}
