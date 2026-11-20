#!/usr/bin/env bash
# Integration test on a disposable Docker host. The coordinator, runner, and jobs share an internal network.
set -euo pipefail
out=$(realpath "${1:?OCI bundle directory required}")
repository=${2:?preloaded local scanner repository required}
digest=$(cat "$out/image-digest.txt")
image="$repository@$digest"
server_image=gitlab/gitlab-ce@sha256:939572df24c6517d0408d7355cafef3f7c6defa9d248201151a88361fc411242
runner_image=gitlab/gitlab-runner@sha256:6d18f8dbc508df95e31ef1329af1fadc4d9f643cb404bc05d3c96beded4725ee
helper_image=gitlab/gitlab-runner-helper@sha256:d8617651f40c9e28ec5e3bf289a0ec77ea1da6b15d53accc26d4e860d934fb5f
for ref in "$server_image" "$runner_image" "$helper_image"; do docker pull "$ref" >/dev/null; done
docker image inspect "$image" >/dev/null

net="pwc-test-net-$$"
server="pwc-gitlab-$$"
runner="pwc-runner-$$"
dir=$(mktemp -d)
cleanup() {
  docker rm -fv "$runner" "$server" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT
docker network create --internal "$net" >/dev/null
test "$(docker network inspect -f '{{.Internal}}' "$net")" = true
docker run -d --pull=never --name "$server" --hostname gitlab.test --network "$net" --network-alias gitlab.test \
  --shm-size=512m -e "GITLAB_OMNIBUS_CONFIG=external_url 'http://gitlab.test'; puma['worker_processes']=0; sidekiq['concurrency']=5; prometheus_monitoring['enable']=false; letsencrypt['enable']=false;" \
  "$server_image" >/dev/null
for ((i=0; i<150; i++)); do
  if docker exec "$server" curl -fsS --max-time 5 http://localhost/-/readiness >/dev/null 2>&1; then break; fi
  sleep 5
done
docker exec "$server" curl -fsS --max-time 10 http://localhost/-/readiness >/dev/null
token=$(docker exec "$server" gitlab-rails runner 'u=User.find_by!(username: "root"); t=u.personal_access_tokens.create!(name: "disposable acceptance", scopes: %w[api create_runner], expires_at: 1.day.from_now.to_date); puts t.token' | tail -1)
test -n "$token"
echo "::add-mask::$token"
api() {
  local endpoint=$1
  shift
  docker exec -i "$server" curl --silent --show-error --fail-with-body --max-time 90 \
    --header "PRIVATE-TOKEN: $token" "$@" "http://localhost/api/v4/$endpoint"
}
project=$(api projects -X POST --data name=offline-fixture --data visibility=private --data initialize_with_readme=true)
pid=$(jq -er .id <<<"$project")
branch=$(jq -er .default_branch <<<"$project")
api "projects/$pid/variables" -X POST --data key=PROTESTWARE_IMAGE_REPOSITORY --data-urlencode "value=$repository" >/dev/null
registration=$(api user/runners -X POST --data runner_type=project_type --data "project_id=$pid" --data run_untagged=true)
runner_id=$(jq -er .id <<<"$registration")
runner_token=$(jq -er .token <<<"$registration")
echo "::add-mask::$runner_token"
docker run --pull=never -d --name "$runner" --network "$net" -v /var/run/docker.sock:/var/run/docker.sock "$runner_image" >/dev/null
docker exec "$runner" gitlab-runner register --non-interactive --url http://gitlab.test --token "$runner_token" \
  --executor docker --docker-image "$image" --docker-helper-image "$helper_image" \
  --docker-network-mode "$net" --docker-pull-policy never
# Only the controller has access to the host daemon. The test jobs receive ordinary build volumes.
commit=$(jq -n --arg branch "$branch" --rawfile ci "$out/gitlab-ci-offline.yml" --rawfile img "$out/protestware-image.yml" \
  '{branch:$branch,commit_message:"Scan an inert fixture",actions:[
    {action:"create",file_path:".gitlab-ci.yml",content:$ci},
    {action:"create",file_path:".gitlab/protestware-image.yml",content:$img},
    {action:"create",file_path:"main.go",content:"package fixture\n"},
    {action:"create",file_path:"Program.cs",content:"namespace Fixture; class Program {}\n"}]}' |
  api "projects/$pid/repository/commits" -X POST -H 'Content-Type: application/json' --data-binary @- | jq -er .id)
for iteration in 1 2; do
  if [[ $iteration == 1 ]]; then
    pipeline=''
    for ((i=0; i<30; i++)); do
      pipeline=$(api "projects/$pid/pipelines?sha=$commit" | jq -r '.[0].id // empty')
      [[ -z $pipeline ]] || break
      sleep 2
    done
    test -n "$pipeline"
  else
    pipeline=$(api "projects/$pid/pipeline" -X POST --data-urlencode "ref=$branch" | jq -er .id)
  fi
  for ((i=0; i<100; i++)); do
    status=$(api "projects/$pid/pipelines/$pipeline" | jq -er .status)
    case "$status" in success|failed|canceled|skipped|manual) break ;; esac
    sleep 3
  done
  jobs=$(api "projects/$pid/pipelines/$pipeline/jobs")
  jq -c '[.[]|{name,status,failure_reason}]' <<<"$jobs"
  if [[ $status != success ]]; then
    # GitLab masks its own tokens. Print only fixed diagnostic categories from runner output.
    while read -r failed; do
      api "projects/$pid/jobs/$failed/trace" | grep -Ei '(permission denied|image.*not present|cannot find|no such file|error:|failed to)' | tail -8 || true
    done < <(jq -r '.[]|select(.status=="failed")|.id' <<<"$jobs")
    exit 1
  fi
  jq -e --argjson rid "$runner_id" 'length==2 and all(.[];.status=="success" and .runner.id==$rid)' <<<"$jobs" >/dev/null
  scan=$(jq -er '.[]|select(.name=="protestware_scan")|.id' <<<"$jobs")
  api "projects/$pid/jobs/$scan/artifacts/.protestware-reports/report.json" |
    jq -eS 'select(.scan.complete and .gate.exit_code==0 and .gate.min_analyzed_files==1 and .ast.parsed>=2) |
            {findings,scan,coverage,ast,gate,analysis_context}' > "$dir/run-$iteration.json"
  test -s "$dir/run-$iteration.json"
  echo "GITLAB_PIPELINE_SUCCESS=$pipeline scanner=$digest runner=$runner_id iteration=$iteration"
done
cmp "$dir/run-1.json" "$dir/run-2.json"
echo 'GITLAB_OFFLINE_REPEAT=identical findings, coverage and gate on a fresh registered runner'
