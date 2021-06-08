module edrint

go 1.16

require (
	github.com/rs/zerolog v1.22.0
	github.com/sharat910/edrint v0.0.0-20210121105758-1d249d6511ee
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
)

replace (
	github.com/sharat910/edrint => ../../
)
