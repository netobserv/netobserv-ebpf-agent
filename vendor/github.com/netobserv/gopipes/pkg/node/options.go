package node

type creationOptions struct {
	// if 0, channel is unbuffered
	channelBufferLen int
}

var defaultOptions = creationOptions{
	channelBufferLen: 0,
}

// CreationOption allows overriding the default values of node instantiation
type CreationOption func(options *creationOptions)

// ChannelBufferLen is a node.CreationOption that allows specifying the length of the input
// channels for a given node. The default value is 0, which means that the channels
// are unbuffered.
func ChannelBufferLen(length int) CreationOption {
	return func(options *creationOptions) {
		options.channelBufferLen = length
	}
}
