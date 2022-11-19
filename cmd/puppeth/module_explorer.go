// Copyright 2017 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/ethereum/go-ethereum/log"
)

// explorerDockerfile is the Dockerfile required to run a block explorer.
var explorerDockerfile = `
FROM sidhujag/syscoin-core:latest as syscoin-alpine
FROM sidhujag/blockscout:latest

ENV SYSCOIN_DATA=/home/syscoin/.syscoin
ENV SYSCOIN_PREFIX=/opt/syscoin
ARG COINSYMBOL={{.Coin}}
ARG EXCHANGE_RATES_COINGECKO_COIN_ID={{.CoingeckoID}}
ARG COINNETWORK={{.Network}}
ARG BLOCK_TRANSFORMER={{.BlockTransformer}}
ARG CSS_PRIMARY={{.CssPrimary}}
ARG CSS_SECONDARY={{.CssSecondary}}
ARG CSS_TERTIARY={{.CssTertiary}}
ARG CSS_PRIMARY_DARK={{.CssPrimaryDark}}
ARG CSS_SECONDARY_DARK={{.CssSecondaryDark}}
ARG CSS_TERTIARY_DARK={{.CssTertiaryDark}}
ARG CSS_FOOTER_BACKGROUND={{.CssFooterBackground}}
ARG CSS_FOOTER_TEXT={{.CssFooterText}}
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/address/_current_coin_balance.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/address/index.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/address/overview.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/block/overview.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/internal_transaction/_tile.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/layout/_topnav.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/layout/app.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/transaction/_pending_tile.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/transaction/_tile.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/templates/transaction/overview.html.eex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/lib/block_scout_web/views/wei_helpers.ex; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/priv/gettext/default.pot; fi
RUN if [ "$COINNETWORK" != "" ]; then sed -i s/"Ether"/"${COINNETWORK}"/g apps/block_scout_web/priv/gettext/en/LC_MESSAGES/default.po; fi


RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"ETH"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/default.pot; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"xDai"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/default.pot; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"ETH"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/en/LC_MESSAGES/default.po; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"xDai"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/en/LC_MESSAGES/default.po; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"xDAI"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/default.pot; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"xDAI"/"${COINSYMBOL}"/g apps/block_scout_web/priv/gettext/en/LC_MESSAGES/default.po; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"xDAI"/"${COINSYMBOL}"/g apps/block_scout_web/lib/block_scout_web/templates/address/overview.html.eex; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"ETH"/"${COINSYMBOL}"/g apps/block_scout_web/lib/block_scout_web/templates/address_token/overview.html.eex; fi
RUN if [ "$COINSYMBOL" != "" ]; then sed -i s/"ETH"/"${COINSYMBOL}"/g apps/block_scout_web/lib/block_scout_web/templates/smart_contract/_functions.html.eex; fi

RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/lib/block_scout_web/templates/address/_tabs.html.eex; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/lib/block_scout_web/templates/address_validation/index.html.eex; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/lib/block_scout_web/views/address_view.ex; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/lib/block_scout_web/templates/layout/_topnav.html.eex; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/lib/block_scout_web/templates/transaction/index.html.eex; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/assets/js/pages/address.js; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/priv/gettext/en/LC_MESSAGES/default.po; fi
RUN if [ "$BLOCK_TRANSFORMER" == "base" ]; then sed -i s/"Validated"/"Mined"/g apps/block_scout_web/priv/gettext/default.pot; fi

RUN if [ "$CSS_PRIMARY" != "" ]; then sed -i s/"#5c34a2"/"${CSS_PRIMARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_PRIMARY" != "" ]; then sed -i s/"#5c34a2"/"${CSS_PRIMARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables-non-critical.scss; fi
RUN if [ "$CSS_PRIMARY" != "" ]; then sed -i s/"#5b389f"/"${CSS_PRIMARY}"/g apps/block_scout_web/assets/css/theme/_base_variables.scss; fi

RUN if [ "$CSS_SECONDARY" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_SECONDARY" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables-non-critical.scss; fi
RUN if [ "$CSS_SECONDARY" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY}"/g apps/block_scout_web/assets/css/theme/_base_variables.scss; fi

RUN if [ "$CSS_TERTIARY" != "" ]; then sed -i s/"#8258cd"/"${CSS_TERTIARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_TERTIARY" != "" ]; then sed -i s/"#bf9cff"/"${CSS_TERTIARY}"/g apps/block_scout_web/assets/css/theme/_neutral_variables-non-critical.scss; fi
RUN if [ "$CSS_TERTIARY" != "" ]; then sed -i s/"#997fdc"/"${CSS_TERTIARY}"/g apps/block_scout_web/assets/css/theme/_base_variables.scss; fi

RUN if [ "$CSS_PRIMARY_DARK" != "" ]; then sed -i s/"#9b62ff"/"${CSS_PRIMARY_DARK}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_PRIMARY_DARK" != "" ]; then sed -i s/"#bf9cff"/"${CSS_PRIMARY_DARK}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_PRIMARY_DARK" != "" ]; then sed -i s/"#9b62ff"/"${CSS_PRIMARY_DARK}"/g apps/block_scout_web/assets/css/theme/_base_variables.scss; fi

RUN if [ "$CSS_SECONDARY_DARK" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY_DARK}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_SECONDARY_DARK" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY_DARK}"/g apps/block_scout_web/assets/css/theme/_neutral_variables-non-critical.scss; fi
RUN if [ "$CSS_SECONDARY_DARK" != "" ]; then sed -i s/"#87e1a9"/"${CSS_SECONDARY_DARK}"/g apps/block_scout_web/assets/css/theme/_base_variables.scss; fi

RUN if [ "$CSS_TERTIARY_DARK" != "" ]; then sed -i s/"#7e50d0"/"${CSS_TERTIARY_DARK}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi

RUN if [ "$CSS_FOOTER_BACKGROUND" != "" ]; then sed -i s/"#3c226a"/"${CSS_FOOTER_BACKGROUND}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi

RUN if [ "$CSS_FOOTER_TEXT" != "" ]; then sed -i s/"#bda6e7"/"${CSS_FOOTER_TEXT}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi
RUN if [ "$CSS_FOOTER_TEXT" != "" ]; then sed -i s/"#dcc8ff"/"${CSS_FOOTER_TEXT}"/g apps/block_scout_web/assets/css/theme/_neutral_variables.scss; fi

RUN if [ "$EXCHANGE_RATES_COINGECKO_COIN_ID" != "" ]; then sed -i s/"ethereum"/"${EXCHANGE_RATES_COINGECKO_COIN_ID}"/g apps/explorer/lib/explorer/exchange_rates/source/coin_gecko.ex; fi
RUN sed -i s/"1 <<< 30"/"50 <<< 30"/g apps/indexer/config/config.exs
RUN sed -i s/"1 <<< 30"/"50 <<< 30"/g apps/indexer/lib/indexer/memory/monitor.ex
RUN sed -i s/"20_000_000"/"200_000_000"/g apps/block_scout_web/lib/block_scout_web/endpoint.ex

RUN mix phx.digest.clean --keep 0

RUN cd apps/block_scout_web/assets/ && \
    npm install && \
    npm run deploy && \
    cd -

RUN cd apps/explorer/ && \
    npm install && \
    cd -

RUN mix phx.digest

RUN rm /usr/local/bin/geth
COPY --from=syscoin-alpine ${SYSCOIN_PREFIX}/bin/syscoind /usr/local/bin/syscoind
COPY --from=syscoin-alpine ${SYSCOIN_PREFIX}/bin/syscoin-cli /usr/local/bin/syscoin-cli
COPY --from=syscoin-alpine ${SYSCOIN_PREFIX}/bin/sysgeth /usr/local/bin/sysgeth
ENV NETWORK={{.Network}} \
    SUBNETWORK={{.SubNetwork}} \
    EXCHANGE_RATES_COINGECKO_COIN_ID={{.CoingeckoID}} \
    COIN={{.Coin}} \
    COIN_NAME={{.Coin}} \
    LOGO={{.Logo}} \
    LOGO_FOOTER={{.LogoFooter}} \
    LOGO_TEXT={{.LogoText}} \
    CHAIN_ID={{.NetworkID}} \
    HEALTHY_BLOCKS_PERIOD={{.HealthyBlockPeriod}} \
    SUPPORTED_CHAINS='{{.SupportedChains}}' \
    BLOCK_TRANSFORMER={{.BlockTransformer}} \
    SHOW_TXS_CHART={{.ShowTxChart}} \
    DISABLE_EXCHANGE_RATES={{.DisableExchangeRates}} \
    SHOW_PRICE_CHART={{.ShowPriceChart}} \
    ETHEREUM_JSONRPC_HTTP_URL={{.HttpUrl}} \
    ETHEREUM_JSONRPC_WS_URL={{.WsUrl}} \
    BLOCKSCOUT_PROTOCOL={{.BlockscoutProtocol}} \
    BLOCKSCOUT_HOST={{.BlockscoutHost}} \
    RE_CAPTCHA_CLIENT_KEY={{.BlockScoutCaptchaSiteKey}} \
    RE_CAPTCHA_SECRET_KEY={{.BlockScoutCaptchaSecretKey}} \
    ENABLE_1559_SUPPORT=true \
    ENABLE_SOURCIFY_INTEGRATION=true \
    DISPLAY_TOKEN_ICONS=true \
    GAS_PRICE=1 \
    SHOW_TESTNET_LABEL={{.ShowTestnetLabel}} \
    ETHEREUM_JSONRPC_DEBUG_TRACE_TRANSACTION_TIMEOUT='15s' \
    FOOTER_CHAT_LINK={{.FooterChat}} \
    FOOTER_FORUM_LINK={{.FooterForum}} \
    FOOTER_GITHUB_LINK={{.FooterGithub}}

RUN apk --no-cache add \
  boost-filesystem \
  boost-system \
  boost-thread \
  libevent \
  libzmq \
  su-exec \
  ca-certificates \
  gmp \
  sqlite-dev

RUN \
	echo $'LC_ALL=C syscoind {{if eq .NetworkID 5700}}--testnet --addnode=52.38.76.82{{end}} --datadir=/opt/app/.syscoin --disablewallet --gethcommandline=--syncmode="full" --gethcommandline=--gcmode="archive" --gethcommandline=--rpc.evmtimeout=10s --gethcommandline=--port={{.EthPort}} --gethcommandline=--bootnodes={{.Bootnodes}} --gethcommandline=--ethstats={{.Ethstats}} --gethcommandline=--cache=8192 --gethcommandline=--http --gethcommandline=--http.api="net,web3,eth,debug,txpool" --gethcommandline=--http.corsdomain="*" --gethcommandline=--http.vhosts="*" --gethcommandline=--ws --gethcommandline=--ws.origins="*" --gethcommandline=--exitwhensynced' >> explorer.sh && \
	echo $'LC_ALL=C exec syscoind {{if eq .NetworkID 5700}}--testnet --addnode=52.38.76.82{{end}} --datadir=/opt/app/.syscoin --disablewallet --gethcommandline=--syncmode="full" --gethcommandline=--gcmode="archive" --gethcommandline=--rpc.evmtimeout=10s --gethcommandline=--port={{.EthPort}} --gethcommandline=--bootnodes={{.Bootnodes}} --gethcommandline=--ethstats={{.Ethstats}} --gethcommandline=--cache=8192 --gethcommandline=--http --gethcommandline=--http.api="net,web3,eth,debug,txpool" --gethcommandline=--http.corsdomain="*" --gethcommandline=--http.vhosts="*" --gethcommandline=--ws --gethcommandline=--ws.origins="*" &' >> explorer.sh && \
    echo '/usr/local/bin/docker-entrypoint.sh postgres &' >> explorer.sh && \
    echo 'sleep 5' >> explorer.sh && \
	echo 'mix do ecto.create, ecto.migrate' >> explorer.sh && \
    echo 'mix phx.server' >> explorer.sh
ENTRYPOINT ["/bin/sh", "explorer.sh"]
`

// explorerComposefile is the docker-compose.yml file required to deploy and
// maintain a block explorer.
var explorerComposefile = `
version: '2'
services:
    explorer:
        build: .
        image: {{.Network}}/explorer
        container_name: {{.Network}}_explorer_1
        ports:
            - "{{.EthPort}}:{{.EthPort}}"
            - "{{.SysPort1}}:{{.SysPort1}}"
            - "{{.SysPort2}}:{{.SysPort2}}"
            - "{{.SysPort3}}:{{.SysPort3}}"
            - "{{.EthPort}}:{{.EthPort}}/udp"{{if not .VHost}}
            - "{{.WebPort}}:4000"{{end}}
        environment:
            - ETH_PORT={{.EthPort}}
            - ETH_NAME={{.EthName}}
            - BLOCK_TRANSFORMER={{.Transformer}}{{if .VHost}}
            - VIRTUAL_HOST={{.VHost}}
            - VIRTUAL_PORT=4000{{end}}
        volumes:
            - {{.Datadir}}:/opt/app/.syscoin
            - {{.DBDir}}:/var/lib/postgresql/data
        logging:
          driver: "json-file"
          options:
            max-size: "1m"
            max-file: "10"
        restart: always
`

// deployExplorer deploys a new block explorer container to a remote machine via
// SSH, docker and docker-compose. If an instance with the specified network name
// already exists there, it will be overwritten!
func deployExplorer(client *sshClient, network string, bootnodes []string, config *explorerInfos, nocache bool, isClique bool) ([]byte, error) {
	// Generate the content to upload to the server
	workdir := fmt.Sprintf("%d", rand.Int63())
	files := make(map[string][]byte)
	transformer := "base"
	if isClique {
		transformer = "clique"
	}
	dockerfile := new(bytes.Buffer)
	subNetwork := ""
	showPriceChart := "true"
	disableExchangeRates := "false"
	showTestnetLabel := "false"
	footerChat := "https://discord.gg/syscoin"
	footerForum := "https://support.syscoin.org/"
	footerGithub := "https://github.com/syscoin/syscoin"
	supportedChains := `[{"title":"Tanenbaum Testnet","url":"https://tanenbaum.io","test_net?":true},{"title":"Syscoin Mainnet","url":"https://explorer.syscoin.org"}]`
	if config.node.network == 5700 {
		subNetwork = "Tanenbaum"
		disableExchangeRates = "true"
		showTestnetLabel = "true"
		showPriceChart = "false"
	}
	protocol := "https"
	host := config.host
	if host == "" {
		host = client.server
		protocol = "http"
	}
	template.Must(template.New("").Parse(explorerDockerfile)).Execute(dockerfile, map[string]interface{}{
		"NetworkID":                  config.node.network,
		"Bootnodes":                  strings.Join(bootnodes, ","),
		"Ethstats":                   config.node.ethstats,
		"EthPort":                    config.node.port,
		"HttpUrl":                    "http://localhost:8545",
		"WsUrl":                      "ws://localhost:8546",
		"Network":                    "Syscoin",
		"SubNetwork":                 subNetwork,
		"CoingeckoID":                "syscoin",
		"Coin":                       "SYS",
		"Logo":                       "/images/sys_logo.svg",
		"LogoFooter":                 "/images/sys_logo.svg",
		"FooterChat":				  footerChat,
		"FooterForum":                footerForum,
		"FooterGithub":               footerGithub,
		"LogoText":                   "NEVM",
		"HealthyBlockPeriod":         34500000,
		"SupportedChains":            supportedChains,
		"BlockTransformer":           transformer,
		"BlockscoutProtocol":         protocol,
		"BlockscoutHost":             host,
		"ShowTxChart":                "true",
		"DisableExchangeRates":       disableExchangeRates,
		"ShowPriceChart":             showPriceChart,
		"ShowTestnetLabel":			  showTestnetLabel,
		"CssPrimary":                 "#243066",
		"CssSecondary":               "#87e1a9",
		"CssTertiary":                "#344180",
		"CssPrimaryDark":             "#6fb8df",
		"CssSecondaryDark":           "#87e1a9",
		"CssTertiaryDark":            "#243066",
		"CssFooterBackground":        "#101d48",
		"CssFooterText":              "#6fb8df",
		"BlockScoutCaptchaSiteKey":   config.blockscoutCaptchaSiteKey,
		"BlockScoutCaptchaSecretKey": config.blockscoutCaptchaSecretKey,
	})
	files[filepath.Join(workdir, "Dockerfile")] = dockerfile.Bytes()

	composefile := new(bytes.Buffer)
	template.Must(template.New("").Parse(explorerComposefile)).Execute(composefile, map[string]interface{}{
		"Network":     network,
		"VHost":       config.host,
		"Ethstats":    config.node.ethstats,
		"Datadir":     config.node.datadir,
		"DBDir":       config.dbdir,
		"EthPort":     config.node.port,
		"SysPort1":    8369,
		"SysPort2":    18369,
		"SysPort3":    18444,
		"EthName":     getEthName(config.node.ethstats),
		"WebPort":     config.port,
		"Transformer": transformer,
	})
	files[filepath.Join(workdir, "docker-compose.yaml")] = composefile.Bytes()
	files[filepath.Join(workdir, "genesis.json")] = config.node.genesis
	// Upload the deployment files to the remote server (and clean up afterwards)
	if out, err := client.Upload(files); err != nil {
		return out, err
	}
	defer client.Run("rm -rf " + workdir)

	// Build and deploy the boot or seal node service
	if nocache {
		return nil, client.Stream(fmt.Sprintf("cd %s && docker-compose -p %s build --pull --no-cache && docker-compose -p %s up -d --force-recreate --timeout 60", workdir, network, network))
	}
	return nil, client.Stream(fmt.Sprintf("cd %s && docker-compose -p %s up -d --build --force-recreate --timeout 60", workdir, network))
}

// explorerInfos is returned from a block explorer status check to allow reporting
// various configuration parameters.
type explorerInfos struct {
	node                       *nodeInfos
	dbdir                      string
	host                       string
	port                       int
	blockscoutCaptchaSiteKey   string
	blockscoutCaptchaSecretKey string
}

// Report converts the typed struct into a plain string->string map, containing
// most - but not all - fields for reporting to the user.
func (info *explorerInfos) Report() map[string]string {
	report := map[string]string{
		"Website address ":        info.host,
		"Website listener port ":  strconv.Itoa(info.port),
		"Ethereum listener port ": strconv.Itoa(info.node.port),
		"Ethstats username":       info.node.ethstats,
	}
	return report
}

// checkExplorer does a health-check against a block explorer server to verify
// whether it's running, and if yes, whether it's responsive.
func checkExplorer(client *sshClient, network string) (*explorerInfos, error) {
	// Inspect a possible explorer container on the host
	infos, err := inspectContainer(client, fmt.Sprintf("%s_explorer_1", network))
	if err != nil {
		return nil, err
	}
	if !infos.running {
		return nil, ErrServiceOffline
	}
	// Resolve the port from the host, or the reverse proxy
	port := infos.portmap["4000/tcp"]
	if port == 0 {
		if proxy, _ := checkNginx(client, network); proxy != nil {
			port = proxy.port
		}
	}
	if port == 0 {
		return nil, ErrNotExposed
	}
	// Resolve the host from the reverse-proxy and the config values
	host := infos.envvars["VIRTUAL_HOST"]
	if host == "" {
		host = client.server
	}
	// Run a sanity check to see if the devp2p is reachable
	p2pPort := infos.portmap[infos.envvars["ETH_PORT"]+"/tcp"]
	if err = checkPort(host, p2pPort); err != nil {
		log.Warn("Explorer node seems unreachable", "server", host, "port", p2pPort, "err", err)
	}
	if err = checkPort(host, port); err != nil {
		log.Warn("Explorer service seems unreachable", "server", host, "port", port, "err", err)
	}
	// Assemble and return the useful infos
	stats := &explorerInfos{
		node: &nodeInfos{
			datadir:  infos.volumes["/opt/app/.syscoin"],
			port:     infos.portmap[infos.envvars["ETH_PORT"]+"/tcp"],
			ethstats: infos.envvars["ETH_NAME"],
		},
		dbdir: infos.volumes["/var/lib/postgresql/data"],
		host:  host,
		port:  port,
	}
	return stats, nil
}
