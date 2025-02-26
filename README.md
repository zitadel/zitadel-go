# ZITADEL GO

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/zitadel-go/workflows/Release/badge.svg)](https://github.com/zitadel/zitadel-go/actions)
[![license](https://badgen.net/github/license/zitadel/zitadel-go/)](https://github.com/zitadel/zitadel-go/blob/main/LICENSE)
[![release](https://badgen.net/github/release/zitadel/zitadel-go/stable)](https://github.com/zitadel/zitadel-go/releases)
[![tag](https://badgen.net/github/tag/zitadel/zitadel-go)](https://github.com/zitadel/zitadel-go/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/zitadel-go)](https://goreportcard.com/report/github.com/zitadel/zitadel-go)
[![codecov](https://codecov.io/gh/zitadel/zitadel-go/branch/main/graph/badge.svg)](https://codecov.io/gh/zitadel/zitadel-go)

Go library for [ZITADEL](https://github.com/zitadel/zitadel).

## Features 

 - Authentication
 - Authorization checks
 - Client for ZITADEL API

## Usage

Add the package to your go.mod by

```
go get -u github.com/zitadel/zitadel-go/v3
```

...and check out the [examples](./example) in this repo or head over to our [docs website](https://zitadel.com/docs/guides/start/quickstart#introduction).

### Versions

If you're looking for older version of this module, please check out the following tags:

- v3.x.x is maintained on the [main](https://github.com/zitadel/zitadel-go/tree/main) branch
- [v2.2.8](https://github.com/zitadel/zitadel-go/releases/tag/v2.2.8) is the last release for the v2 Go module
- [v0.3.5](https://github.com/zitadel/zitadel-go/releases/tag/v0.3.5) is the last release for the v0/v1 Go module

Currently only v3 is supported, due to some security updates that involve breaking changes. Therefore v2 and older will no longer be supported.

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).  
Versions that also build are marked with :warning:.

| Version | Supported          |
|---------|--------------------|
| <1.21   | :x:                |
| 1.21    | :warning:          |
| 1.22    | :white_check_mark: |
| 1.23    | :white_check_mark: |

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Contributors

<a href="https://github.com/zitadel/zitadel-go/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zitadel/zitadel-go" />
</a>
