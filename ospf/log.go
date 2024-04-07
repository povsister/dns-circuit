package ospf

import (
	"fmt"
	"time"
)

func timeNowStr() string {
	return time.Now().Format("15:04:05.000") + " "
}

func logDebug(format string, args ...interface{}) {
	fmt.Printf(timeNowStr()+"[DBG] "+format+"\n\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf(timeNowStr()+"[WRN] "+format+"\n\n", args...)
}

func logErr(format string, args ...interface{}) {
	fmt.Printf(timeNowStr()+"[ERR] "+format+"\n\n", args...)
}
