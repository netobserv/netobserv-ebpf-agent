#!/usr/bin/env bash

set -e

tekt_y_pr="./.tekton/netobserv-ebpf-agent-ystream-pull-request.yaml"
tekt_y_ps="./.tekton/netobserv-ebpf-agent-ystream-push.yaml"
tekt_z_pr="./.tekton/netobserv-ebpf-agent-zstream-pull-request.yaml"
tekt_z_ps="./.tekton/netobserv-ebpf-agent-zstream-push.yaml"

current=`sed -r 's/BUILDVERSION=(.+)/\1/' ./Dockerfile-args.downstream`
x=`echo ${current} | cut -d . -f1`
y=`echo ${current} | cut -d . -f2`
z=`echo ${current} | cut -d . -f3`
release_branch="release-${x}.${y}"

initial_branch=`git rev-parse --abbrev-ref HEAD`
restore_branch() {
  branch=`git rev-parse --abbrev-ref HEAD`
  if [[ $branch != $initial_branch ]]; then
    echo "Restoring checked-out branch"
    git checkout $initial_branch
  fi
}
trap restore_branch EXIT

echo "This script should run from the branch that was just released: it uses the current version, as defined in Dockerfile-args.downstream, to know which branches to update."
echo "Current version detected: $current"
if [[ "${z}" == "0" ]]; then
  next_y="$x.$((y+1)).$z"
  next_z="$x.$y.$((z+1))"
  echo "Next versions to prepare:"
  echo "- ${next_y} for branch 'main' (changes will be done on the local branch 'next-main', so make sure it's fine to overwrite before you continue)"
  echo "- ${next_z} for branch '${release_branch}' (changes will be done on the local branch 'next-${release_branch}', so make sure it's fine to overwrite before you continue)"
else
  next_z="$x.$y.$((z+1))"
  echo "Next version to prepare:"
  echo "- ${next_z} for branch '${release_branch}' (changes will be done on the local branch 'next-${release_branch}', so make sure it's fine to overwrite before you continue)"
fi
read -p "Is it correct? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
  exit 0
fi

git fetch upstream

echo ""
echo "Preparing next-${release_branch} for ${next_z}"
git branch -D next-${release_branch} || true
git checkout -b next-${release_branch} upstream/${release_branch}

echo "Updating Dockerfile-args.downstream..."
sed -i -r "s/^BUILDVERSION=.+/BUILDVERSION=${next_z}/" ./Dockerfile-args.downstream

check_tekton_z() {
  local tekt_y=$1
  local tekt_z=$2

  if [[ -f $tekt_y ]]; then
    if [[ ! -f $tekt_z ]]; then
      echo "  Converting $tekt_y to zstream..."
      mv $tekt_y $tekt_z
      sed -i -r "s/ystream/zstream/g" $tekt_z
    else
      echo "  WARNING: both ystream and zstream files found ($tekt_y, $tekt_z); please double-check the configuration, should be only one."
    fi
  elif [[ -f $tekt_z ]]; then
    echo "  No ystream conversion needed"
  else
    echo "  ERROR: missing tekton files ($tekt_y or $tekt_z)"
    exit -1
  fi
  echo "  Setting branch '${release_branch}' in $tekt_z..."
  sed -i -r "s/\"(main|release-[0-9]+\.[0-9]+)\"/\"${release_branch}\"/g" $tekt_z
}

echo "Checking for .tekton files..."
check_tekton_z $tekt_y_pr $tekt_z_pr
check_tekton_z $tekt_y_ps $tekt_z_ps

git add -A

echo ""
echo "$next_z done!"
echo "Before we commit, double-check the changes. In summary, we expect:"
echo "- The Dockerfile-args.downstream file to point to the next version ($next_z)"
echo "- The tekton pipelines (on-push and on-pull-request) to have their on-cel-expression hook targetting the desired branch ($release_branch)"
echo "- The tekton pipelines (on-push and on-pull-request) to point to zstream in Konflux/quay/etc."
echo ""
echo "You can also bring manual changes before coming back here and continue."
echo ""

read -p "Looks good to you? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
  exit 0
fi

git commit --allow-empty -m "Prepare $next_z"

check_tekton_y() {
  local tekt_y=$1
  local tekt_z=$2
  if [[ -f $tekt_y ]]; then
    echo "  There should be no change to bring in $tekt_y"
  else
    echo "  ERROR: missing tekton file $tekt_y"
    exit -1
  fi
  if [[ -f $tekt_z ]]; then
    echo "  WARNING: unexpected zstream file found ($tekt_z); branching issue? Please double-check the configuration, it shouldn't be there."
  fi
}

if [[ "${z}" == "0" ]]; then
  echo "Preparing next-main for ${next_y}"
  git branch -D next-main || true
  git checkout -b next-main upstream/main

  echo "Updating Dockerfile-args.downstream..."
  sed -i -r "s/^BUILDVERSION=.+/BUILDVERSION=${next_y}/" ./Dockerfile-args.downstream

  echo "Checking for .tekton files..."
  check_tekton_y $tekt_y_pr $tekt_z_pr
  check_tekton_y $tekt_y_ps $tekt_z_ps
  git add -A

  echo ""
  echo "$next_y done!"
  echo "Before we commit, double-check the changes. In summary, we expect:"
  echo "- The Dockerfile-args.downstream file to point to the next version ($next_y)"
  echo "- The tekton pipelines (on-push and on-pull-request) to have their on-cel-expression hook targetting the desired branch (main)"
  echo "- The tekton pipelines (on-push and on-pull-request) to point to ystream in Konflux/quay/etc."
  echo ""
  echo "You can also bring manual changes before coming back here and continue."
  echo ""

  read -p "Looks good to you? [y/N] " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]
  then
    exit 0
  fi

  git commit --allow-empty -m "Prepare $next_y"
fi

echo ""
echo "🤞 You should be all good to push to upstream 🤞"
