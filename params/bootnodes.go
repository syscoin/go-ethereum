// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// SYSCOIN MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Syscoin network.
var MainnetBootnodes = []string{
	"enode://6f417e6740e559818cedd1ae31ea339657f4580c06491ab9c9a7be9dc9136e858e5bc9a3c2e8d6ea49567af5102afced9d8a99c04410244b0c0880911720439a@54.203.37.244:30303",
}

// SepoliaBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Sepolia test network.
var SepoliaBootnodes = []string{
	// EF DevOps
	"enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303", // sepolia-bootnode-1-nyc3
	"enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303",  // sepolia-bootnode-1-sfo3
	"enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303",  // sepolia-bootnode-1-syd1
	"enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303",  // sepolia-bootnode-1-blr1
	"enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303", // sepolia-bootnode-1-ams3
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
	"enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303", // IE
	"enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30303", // AKASHA
}

// GoerliBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Görli test network.
var GoerliBootnodes = []string{
	// Upstream bootnodes
	"enode://011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a@51.141.78.53:30303",
	"enode://176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b@13.93.54.137:30303",
	"enode://46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291@94.237.54.114:30313",
	"enode://b5948a2d3e9d486c4d75bf32713221c2bd6cf86463302339299bd227dc2e276cd5a1c7ca4f43a0e9122fe9af884efed563bd2a1fd28661f3b5f5ad7bf1de5949@18.218.250.66:30303",

	// Ethereum Foundation bootnode
	"enode://a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91@3.11.147.67:30303",

	// Goerli Initiative bootnodes
	"enode://d4f764a48ec2a8ecf883735776fdefe0a3949eb0ca476bd7bc8d0954a9defe8fea15ae5da7d40b5d2d59ce9524a99daedadf6da6283fca492cc80b53689fb3b3@46.4.99.122:32109",
	"enode://d2b720352e8216c9efc470091aa91ddafc53e222b32780f505c817ceef69e01d5b0b0797b69db254c586f493872352f5a022b4d8479a00fc92ec55f9ad46a27e@88.99.70.182:30303",
}
// SYSCOIN
var TanenbaumBootnodes = []string{
	"enode://f0e3e91d3d28b808734ce08b10855b5e6b6bde8eb9e4bedaf8aababc2ceaa8f4134cec309a996765f183361f1e67bce341326c05b743ed5932a8e705149364e4@44.238.217.166:30303",
}

var V5Bootnodes = []string{
	"",
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	case MainnetGenesisHash:
		net = "mainnet"
	case RinkebyGenesisHash:
		net = "rinkeby"
	case GoerliGenesisHash:
		net = "goerli"
	case TanenbaumGenesisHash:
		net = "tanenbaum"
	case SepoliaGenesisHash:
		net = "sepolia"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
