package logger

import (
	"github.com/HanHongChen/dp-udp/constant"
	loggergo "github.com/Alonza0314/logger-go/v2"
	loggergoModel "github.com/Alonza0314/logger-go/v2/model"
	loggergoUtil "github.com/Alonza0314/logger-go/v2/util"
)

type ServerLogger struct {
	*loggergo.Logger

	CfgLog    loggergoModel.LoggerInterface
	ServerLog loggergoModel.LoggerInterface
	Udp1Log   loggergoModel.LoggerInterface
	Udp2Log   loggergoModel.LoggerInterface
	TunLog    loggergoModel.LoggerInterface
}

func NewServerLogger(level loggergoUtil.LogLevelString, filePath string, debugMode bool) *ServerLogger {
	logger := loggergo.NewLogger(filePath, debugMode)
	logger.SetLevel(level)
	return &ServerLogger{
		Logger: logger,

		CfgLog:    logger.WithTags(constant.SERVER_TAG, constant.CONFIG_TAG),
		ServerLog: logger.WithTags(constant.SERVER_TAG, constant.SERVER_TAG),
		Udp1Log:   logger.WithTags(constant.SERVER_TAG, constant.UDP_1_TAG),
		Udp2Log:   logger.WithTags(constant.SERVER_TAG, constant.UDP_2_TAG),
		TunLog:    logger.WithTags(constant.SERVER_TAG, constant.TUN_TAG),
	}
}
