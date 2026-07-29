package runtime

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// devLogFile is where the development logger mirrors its output. Keeping a
// rolling, plain-text copy on disk (in addition to stderr) lets tooling and
// local hot-reload setups tail the server's lifecycle, request, and esbuild
// compilation logs without scraping the terminal. Production uses the JSON
// logger and never writes this file. The file is listed in .gitignore.
const devLogFile = ".vault3.log"

// newLogger builds the process logger. In production it is the standard zap
// JSON logger. In development it tees the human-readable console output to
// both stderr and .vault3.log so the running server's logs can be read back
// from a file. A failure to open the log file degrades gracefully to
// stderr-only rather than blocking startup.
func newLogger(production bool) (*zap.Logger, error) {
	if production {
		return zap.NewProduction()
	}

	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stderr), zapcore.DebugLevel)

	file, openErr := os.OpenFile(devLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if openErr != nil {
		return zap.New(consoleCore, zap.AddCaller()), nil
	}

	fileCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(file), zapcore.DebugLevel)
	return zap.New(zapcore.NewTee(consoleCore, fileCore), zap.AddCaller()), nil
}
