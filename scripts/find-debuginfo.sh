#!/bin/bash
#find-debuginfo.sh - automagically generate debug info and file list
#for inclusion in an rpm spec file.
#
# Usage: find-debuginfo.sh [--strict-build-id] [-g] [-r] [-m] [-i] [-n]
#			   [--keep-section SECTION] [--remove-section SECTION]
#	 		   [-j N] [--jobs N]
#	 		   [-o debugfiles.list]
#	 		   [-S debugsourcefiles.list]
#			   [--run-dwz] [--dwz-low-mem-die-limit N]
#			   [--dwz-max-die-limit N]
#			   [--build-id-seed SEED]
#			   [--unique-debug-suffix SUFFIX]
#			   [--unique-debug-src-base BASE]
#			   [[-l filelist]... [-p 'pattern'] -o debuginfo.list]
#			   [builddir]
#
# The -g flag says to use strip -g instead of full strip on DSOs or EXEs.
# The -r flag says to use eu-strip --reloc-debug-sections.
# Use --keep-section SECTION or --remove-section SECTION to explicitly
# keep a (non-allocated) section in the main executable or explicitly
# remove it into the .debug file. SECTION is an extended wildcard pattern.
# Both options can be given more than once.
#
# The --strict-build-id flag says to exit with failure status if
# any ELF binary processed fails to contain a build-id note.
# The -m flag says to include a .gnu_debugdata section in the main binary.
# The -i flag says to include a .gdb_index section in the .debug file.
# The -n flag says to not recompute the build-id.
#
# The -j, --jobs N option will spawn N processes to do the debuginfo
# extraction in parallel.
#
# A single -o switch before any -l or -p switches simply renames
# the primary output file from debugfiles.list to something else.
# A -o switch that follows a -p switch or some -l switches produces
# an additional output file with the debuginfo for the files in
# the -l filelist file, or whose names match the -p pattern.
# The -p argument is an grep -E -style regexp matching the a file name,
# and must not use anchors (^ or $).
#
# The --run-dwz flag instructs find-debuginfo.sh to run the dwz utility
# if available, and --dwz-low-mem-die-limit and --dwz-max-die-limit
# provide detailed limits.  See dwz(1) -l and -L option for details.
#
# If --build-id-seed SEED is given then debugedit is called to
# update the build-ids it finds adding the SEED as seed to recalculate
# the build-id hash.  This makes sure the build-ids in the ELF files
# are unique between versions and releases of the same package.
# (Use --build-id-seed "%{VERSION}-%{RELEASE}".)
#
# If --unique-debug-suffix SUFFIX is given then the debug files created
# for <FILE> will be named <FILE>-<SUFFIX>.debug.  This makes sure .debug
# are unique between package version, release and architecture.
# (Use --unique-debug-suffix "-%{VERSION}-%{RELEASE}.%{_arch}".)
#
# If --unique-debug-src-base BASE is given then the source directory
# will be called /usr/debug/src/<BASE>.  This makes sure the debug source
# directories are unique between package version, release and architecture.
# (Use --unique-debug-src-base "%{name}-%{VERSION}-%{RELEASE}.%{_arch}".)
#
# All file names in switches are relative to builddir (. if not given).
#

# Figure out where we are installed so we can call other helper scripts.
lib_rpm_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# With -g arg, pass it to strip on libraries or executables.
strip_g=false

# with -r arg, pass --reloc-debug-sections to eu-strip.
strip_r=false

# keep or remove arguments to eu-strip.
keep_remove_args=

# with -m arg, add minimal debuginfo to binary.
include_minidebug=false

# with -i arg, add GDB index to .debug file.
include_gdb_index=false

# Barf on missing build IDs.
strict=false

# Do not recompute build IDs.
no_recompute_build_id=false

# DWZ parameters.
run_dwz=false
dwz_low_mem_die_limit=
dwz_max_die_limit=

# build id seed given by the --build-id-seed option
build_id_seed=

# Arch given by --unique-debug-arch
unique_debug_suffix=

# Base given by --unique-debug-src-base
unique_debug_src_base=

# Number of parallel jobs to spawn
n_jobs=1

BUILDDIR=.
out=debugfiles.list
srcout=
nout=0
while [ $# -gt 0 ]; do
  case "$1" in
  --strict-build-id)
    strict=true
    ;;
  --run-dwz)
    run_dwz=true
    ;;
  --dwz-low-mem-die-limit)
    dwz_low_mem_die_limit=$2
    shift
    ;;
  --dwz-max-die-limit)
    dwz_max_die_limit=$2
    shift
    ;;
  --build-id-seed)
    build_id_seed=$2
    shift
    ;;
  --unique-debug-suffix)
    unique_debug_suffix=$2
    shift
    ;;
  --unique-debug-src-base)
    unique_debug_src_base=$2
    shift
    ;;
  -g)
    strip_g=true
    ;;
  -m)
    include_minidebug=true
    ;;
  -n)
    no_recompute_build_id=true
    ;;
  -i)
    include_gdb_index=true
    ;;
  -o)
    if [ -z "${lists[$nout]}" -a -z "${ptns[$nout]}" ]; then
      out=$2
    else
      outs[$nout]=$2
      ((nout++))
    fi
    shift
    ;;
  -l)
    lists[$nout]="${lists[$nout]} $2"
    shift
    ;;
  -p)
    ptns[$nout]=$2
    shift
    ;;
  -r)
    strip_r=true
    ;;
  --keep-section)
    keep_remove_args="${keep_remove_args} --keep-section $2"
    shift
    ;;
  --remove-section)
    keep_remove_args="${keep_remove_args} --remove-section $2"
    shift
    ;;
  -j)
    n_jobs=$2
    shift
    ;;
  -j*)
    n_jobs=${1#-j}
    ;;
  --jobs)
    n_jobs=$2
    shift
    ;;
  -S)
    srcout=$2
    shift
    ;;
  *)
    BUILDDIR=$1
    shift
    break
    ;;
  esac
  shift
done

if test -n "$build_id_seed" -a "$no_recompute_build_id" = "true"; then
  echo >&2 "*** ERROR: --build-id-seed (unique build-ids) and -n (do not recompute build-id) cannot be used together"
  exit 2
fi

i=0
while ((i < nout)); do
  outs[$i]="$BUILDDIR/${outs[$i]}"
  l=''
  for f in ${lists[$i]}; do
    l="$l $BUILDDIR/$f"
  done
  lists[$i]=$l
  ((++i))
done

LISTFILE="$BUILDDIR/$out"
SOURCEFILE="$BUILDDIR/debugsources.list"
LINKSFILE="$BUILDDIR/debuglinks.list"
ELFBINSFILE="$BUILDDIR/elfbins.list"

> "$SOURCEFILE"
> "$LISTFILE"
> "$LINKSFILE"
> "$ELFBINSFILE"

debugdir="${RPM_BUILD_ROOT}/usr/lib/debug"

strip_to_debug()
{
  local g=
  local r=
  $strip_r && r=--reloc-debug-sections
  $strip_g && case "$(file -bi "$2")" in
  application/x-sharedlib*) g=-g ;;
  application/x-executable*) g=-g ;;
  application/x-pie-executable*) g=-g ;;
  esac
  eu-strip -p --remove-comment $r $g ${keep_remove_args} -f "$1" "$2" || exit
  chmod 444 "$1" || exit
}

add_minidebug()
{
  local debuginfo="$1"
  local binary="$2"

  local dynsyms=`mktemp`
  local funcsyms=`mktemp`
  local keep_symbols=`mktemp`
  local mini_debuginfo=`mktemp`

  # In the minisymtab we don't need the .debug_ sections (already removed
  # by -S) but also not other non-allocated PROGBITS, NOTE or NOBITS sections.
  # List and remove them explicitly. We do want to keep the allocated,
  # symbol and NOBITS sections so cannot use --keep-only because that is
  # too aggressive. Field $2 is the section name, $3 is the section type
  # and $8 are the section flags.
  local remove_sections=`readelf -W -S "$debuginfo" \
	| awk '{ if (index($2,".debug_") != 1 \
		     && ($3 == "PROGBITS" || $3 == "NOTE" || $3 == "NOBITS") \
		     && index($8,"A") == 0) \
		   printf "--remove-section "$2" " }'`

  # Extract the dynamic symbols from the main binary, there is no need to also have these
  # in the normal symbol table
  nm -D "$binary" --format=posix --defined-only | awk '{ print $1 }' | sort > "$dynsyms"
  # Extract all the text (i.e. function) symbols from the debuginfo
  # Use format sysv to make sure we can match against the actual ELF FUNC
  # symbol type. The binutils nm posix format symbol type chars are
  # ambigous for architectures that might use function descriptors.
  nm "$debuginfo" --format=sysv --defined-only | awk -F \| '{ if ($4 ~ "FUNC") print $1 }' | sort > "$funcsyms"
  # Keep all the function symbols not already in the dynamic symbol table
  comm -13 "$dynsyms" "$funcsyms" > "$keep_symbols"
  # Copy the full debuginfo, keeping only a minumal set of symbols and removing some unnecessary sections
  objcopy -S $remove_sections --keep-symbols="$keep_symbols" "$debuginfo" "$mini_debuginfo" &> /dev/null
  #Inject the compressed data into the .gnu_debugdata section of the original binary
  xz "$mini_debuginfo"
  mini_debuginfo="${mini_debuginfo}.xz"
  objcopy --add-section .gnu_debugdata="$mini_debuginfo" "$binary"
  rm -f "$dynsyms" "$funcsyms" "$keep_symbols" "$mini_debuginfo"
}

# Make a relative symlink to $1 called $3$2
shopt -s extglob
link_relative()
{
  local t="$1" f="$2" pfx="$3"
  local fn="${f#/}" tn="${t#/}"
  local fd td d

  while fd="${fn%%/*}"; td="${tn%%/*}"; [ "$fd" = "$td" ]; do
    fn="${fn#*/}"
    tn="${tn#*/}"
  done

  d="${fn%/*}"
  if [ "$d" != "$fn" ]; then
    d="${d//+([!\/])/..}"
    tn="${d}/${tn}"
  fi

  mkdir -p "$(dirname "$pfx$f")" && ln -snf "$tn" "$pfx$f"
}

# Make a symlink in /usr/lib/debug/$2 to $1
debug_link()
{
  local l="/usr/lib/debug$2"
  local t="$1"
  echo >> "$LINKSFILE" "$l $t"
  link_relative "$t" "$l" "$RPM_BUILD_ROOT"
}

get_debugfn()
{
  dn=$(dirname "${1#$RPM_BUILD_ROOT}")
  bn=$(basename "$1" .debug)${unique_debug_suffix}.debug
  debugdn=${debugdir}${dn}
  debugfn=${debugdn}/${bn}
}

set -o pipefail

strict_error=ERROR
$strict || strict_error=WARNING

temp=$(mktemp -d ${TMPDIR:-/tmp}/find-debuginfo.XXXXXX)
trap 'rm -rf "$temp"' EXIT

# Build a list of unstripped ELF files and their hardlinks
# (also consider non-static libraries)
touch "$temp/primary"
find "$RPM_BUILD_ROOT" ! -path "${debugdir}/*.debug" -type f \
     		     \( -perm -0100 -or -perm -0010 -or -perm -0001 \) \
		     ! -name "*.a" ! -name "ld-*.so" ! -name "ld-linux-x86-64.so*" \
		     -print |
file -N -f - | sed -n -e 's/^\(.*\):[ 	]*.*ELF.*, not stripped.*/\1/p' |
xargs --no-run-if-empty stat -c '%h %D_%i %n' |
while read nlinks inum f; do
  if [ $nlinks -gt 1 ]; then
    var=seen_$inum
    if test -n "${!var}"; then
      echo "$inum $f" >>"$temp/linked"
      continue
    else
      read "$var" < <(echo 1)
    fi
  fi
  echo "$nlinks $inum $f" >>"$temp/primary"
done

# Strip ELF binaries
do_file()
{
  local nlinks=$1 inum=$2 f=$3 id link linked

  get_debugfn "$f"
  [ -f "${debugfn}" ] && return

  echo "extracting debug info from $f"
  # See also cpio SOURCEFILE copy. Directories must match up.
  debug_base_name="$RPM_BUILD_DIR"
  debug_dest_name="/usr/src/debug"
  if [ ! -z "$unique_debug_src_base" ]; then
    debug_base_name="$BUILDDIR"
    debug_dest_name="/usr/src/debug/${unique_debug_src_base}"
  fi
  no_recompute=
  if [ "$no_recompute_build_id" = "true" ]; then
    no_recompute="-n"
  fi
  id=$(${lib_rpm_dir}/debugedit -b "$debug_base_name" -d "$debug_dest_name" \
			      $no_recompute -i \
			      ${build_id_seed:+--build-id-seed="$build_id_seed"} \
			      -l "$SOURCEFILE" "$f") || return
  if [ -z "$id" ]; then
    echo >&2 "*** ${strict_error}: No build ID note found in $f"
  fi

  # Add .gdb_index if requested.
  if $include_gdb_index; then
    if type gdb-add-index >/dev/null 2>&1; then
      gdb-add-index "$f"
    else
      echo >&2 "*** ERROR: GDB index requested, but no gdb-add-index installed"
      exit 2
    fi
  fi

  # A binary already copied into /usr/lib/debug doesn't get stripped,
  # just has its file names collected and adjusted.
  case "$dn" in
  /usr/lib/debug/*)
    return ;;
  esac

  mkdir -p "${debugdn}"
  if [ -e "${BUILDDIR}/Kconfig" ] ; then
      mode=$(stat -c %a "$f")
      chmod +w "$f"
      objcopy --only-keep-debug $f $debugfn || :
      (
	  shopt -s extglob
	  strip_option="--strip-all"
	  case "$f" in
	      *.ko)
		  strip_option="--strip-debug" ;;
	      *$STRIP_KEEP_SYMTAB*)
		  if test -n "$STRIP_KEEP_SYMTAB"; then
		      strip_option="--strip-debug"
		  fi
		  ;;
	  esac
	  if test "$NO_DEBUGINFO_STRIP_DEBUG" = true ; then
	      strip_option=
	  fi
	  objcopy --add-gnu-debuglink=$debugfn -R .comment -R .GCC.command.line $strip_option $f
	  chmod $mode $f
      ) || :
  else
      if test -w "$f"; then
	  strip_to_debug "${debugfn}" "$f"
      else
	  chmod u+w "$f"
	  strip_to_debug "${debugfn}" "$f"
	  chmod u-w "$f"
      fi
  fi

  # strip -g implies we have full symtab, don't add mini symtab in that case.
  # It only makes sense to add a minisymtab for executables and shared
  # libraries. Other executable ELF files (like kernel modules) don't need it.
  if [ "$include_minidebug" = "true" -a "$strip_g" = "false" ]; then
    skip_mini=true
    case "$(file -bi "$f")" in
      application/x-sharedlib*) skip_mini=false ;;
      application/x-executable*) skip_mini=false ;;
    esac
    $skip_mini || add_minidebug "${debugfn}" "$f"
  fi

  echo "./${f#$RPM_BUILD_ROOT}" >> "$ELFBINSFILE"

  # If this file has multiple links, make the corresponding .debug files
  # all links to one file too.
  if [ $nlinks -gt 1 ]; then
    grep "^$inum " "$temp/linked" | while read inum linked; do
      link=$debugfn
      get_debugfn "$linked"
      echo "hard linked $link to $debugfn"
      mkdir -p "$(dirname "$debugfn")" && ln -nf "$link" "$debugfn"
    done
  fi
}

# 16^6 - 1 or about 16 million files
FILENUM_DIGITS=6
run_job()
{
  local jobid=$1 filenum
  local SOURCEFILE=$temp/debugsources.$jobid ELFBINSFILE=$temp/elfbins.$jobid

  >"$SOURCEFILE"
  >"$ELFBINSFILE"
  # can't use read -n <n>, because it reads bytes one by one, allowing for
  # races
  while :; do
    filenum=$(dd bs=$(( FILENUM_DIGITS + 1 )) count=1 status=none)
    if test -z "$filenum"; then
      break
    fi
    do_file $(sed -n "$(( 0x$filenum )) p" "$temp/primary")
  done
  echo 0 >"$temp/res.$jobid"
}

n_files=$(wc -l <"$temp/primary")
if [ $n_jobs -gt $n_files ]; then
  n_jobs=$n_files
fi
if [ $n_jobs -le 1 ]; then
  while read nlinks inum f; do
    do_file "$nlinks" "$inum" "$f"
  done <"$temp/primary"
else
  for ((i = 1; i <= n_files; i++)); do
    printf "%0${FILENUM_DIGITS}x\\n" $i
  done | (
    exec 3<&0
    for ((i = 0; i < n_jobs; i++)); do
      # The shell redirects stdin to /dev/null for background jobs. Work
      # around this by duplicating fd 0
      run_job $i <&3 &
    done
    wait
  )
  for f in "$temp"/res.*; do
    res=$(< "$f")
    if [ "$res" !=  "0" ]; then
      exit 1
    fi
  done
  cat "$temp"/debugsources.* >"$SOURCEFILE"
  cat "$temp"/elfbins.* >"$ELFBINSFILE"
fi

# Invoke the DWARF Compressor utility.
if $run_dwz \
   && [ -d "${RPM_BUILD_ROOT}/usr/lib/debug" ]; then
  readarray dwz_files < <(cd "${RPM_BUILD_ROOT}/usr/lib/debug"; find -type f -name \*.debug | LC_ALL=C sort)
  if [ ${#dwz_files[@]} -gt 0 ]; then
    dwz_multifile_name="${RPM_PACKAGE_NAME}-${RPM_PACKAGE_VERSION}-${RPM_PACKAGE_RELEASE}.${RPM_ARCH}"
    dwz_multifile_suffix=
    dwz_multifile_idx=0
    while [ -f "${RPM_BUILD_ROOT}/usr/lib/debug/.dwz/${dwz_multifile_name}${dwz_multifile_suffix}" ]; do
      let ++dwz_multifile_idx
      dwz_multifile_suffix=".${dwz_multifile_idx}"
    done
    dwz_multifile_name="${dwz_multifile_name}${dwz_multifile_suffix}"
    dwz_opts="-h -q -r"
    [ ${#dwz_files[@]} -gt 1 ] \
      && dwz_opts="${dwz_opts} -m .dwz/${dwz_multifile_name}"
    mkdir -p "${RPM_BUILD_ROOT}/usr/lib/debug/.dwz"
    [ -n "${dwz_low_mem_die_limit}" ] \
      && dwz_opts="${dwz_opts} -l ${dwz_low_mem_die_limit}"
    [ -n "${dwz_max_die_limit}" ] \
      && dwz_opts="${dwz_opts} -L ${dwz_max_die_limit}"
    if type dwz >/dev/null 2>&1; then
      ( cd "${RPM_BUILD_ROOT}/usr/lib/debug" && dwz $dwz_opts ${dwz_files[@]} )
    else
      echo >&2 "*** ERROR: DWARF compression requested, but no dwz installed"
      exit 2
    fi
    # Remove .dwz directory if empty
    rmdir "${RPM_BUILD_ROOT}/usr/lib/debug/.dwz" 2>/dev/null
    if [ -f "${RPM_BUILD_ROOT}/usr/lib/debug/.dwz/${dwz_multifile_name}" ]; then
      id="`readelf -Wn "${RPM_BUILD_ROOT}/usr/lib/debug/.dwz/${dwz_multifile_name}" \
	     2>/dev/null | sed -n 's/^    Build ID: \([0-9a-f]\+\)/\1/p'`"
    fi

    # dwz invalidates .gnu_debuglink CRC32 in the main files.
    cat "$ELFBINSFILE" |
    (cd "$RPM_BUILD_ROOT"; \
     xargs -d '\n' ${lib_rpm_dir}/sepdebugcrcfix usr/lib/debug)
  fi
fi

# For each symlink whose target has a .debug file,
# make a .debug symlink to that file.
find "$RPM_BUILD_ROOT" ! -path "${debugdir}/*" -type l -print |
while read f
do
  t=$(readlink -m "$f").debug
  f=${f#$RPM_BUILD_ROOT}
  t=${t#$RPM_BUILD_ROOT}
  if [ -f "$debugdir$t" ]; then
    echo "symlinked /usr/lib/debug$t to /usr/lib/debug${f}.debug"
    debug_link "/usr/lib/debug$t" "${f}.debug"
  fi
done

if [ -s "$SOURCEFILE" ]; then
  # See also debugedit invocation. Directories must match up.
  debug_base_name="$RPM_BUILD_DIR"
  debug_dest_name="/usr/src/debug"
  if [ ! -z "$unique_debug_src_base" ]; then
    debug_base_name="$BUILDDIR"
    debug_dest_name="/usr/src/debug/${unique_debug_src_base}"
  fi

  mkdir -p "${RPM_BUILD_ROOT}${debug_dest_name}"
  # Filter out anything compiler generated which isn't a source file.
  # e.g. <internal>, <built-in>, <__thread_local_inner macros>.
  # Some compilers generate them as if they are part of the working
  # directory (which is why we match against ^ or /).
  LC_ALL=C sort -z -u "$SOURCEFILE" | grep -E -v -z '(^|/)<[a-z _-]+>$' |
  (cd "${debug_base_name}"; cpio -pd0mL "${RPM_BUILD_ROOT}${debug_dest_name}")
  # stupid cpio creates new directories in mode 0700,
  # and non-standard modes may be inherented from original directories, fixup
  find "${RPM_BUILD_ROOT}${debug_dest_name}" -type d -print0 |
  xargs --no-run-if-empty -0 chmod 0755
fi

if [ -d "${RPM_BUILD_ROOT}/usr/lib" -o -d "${RPM_BUILD_ROOT}/usr/src" ]; then
  ((nout > 0)) ||
  test ! -d "${RPM_BUILD_ROOT}/usr/lib" ||
  (cd "${RPM_BUILD_ROOT}/usr/lib"; find debug -type d) |
  sed 's,^,%dir /usr/lib/,' >> "$LISTFILE"

  (cd "${RPM_BUILD_ROOT}/usr"
   test ! -d lib/debug || find lib/debug ! -type d
   test ! -d src/debug -o -n "$srcout" || find src/debug -mindepth 1 -maxdepth 1
  ) | sed 's,^,/usr/,' >> "$LISTFILE"
fi

if [ -n "$srcout" ]; then
  srcout="$BUILDDIR/$srcout"
  > "$srcout"
  if [ -d "${RPM_BUILD_ROOT}/usr/src/debug" ]; then
    (cd "${RPM_BUILD_ROOT}/usr"
     find src/debug -mindepth 1 -maxdepth 1
    ) | sed 's,^,/usr/,' >> "$srcout"
  fi
fi

# Append to $1 only the lines from stdin not already in the file.
append_uniq()
{
  grep -F -f "$1" -x -v >> "$1"
}

# Helper to generate list of corresponding .debug files from a file list.
filelist_debugfiles()
{
  local extra="$1"
  shift
  sed 's/^%[a-z0-9_][a-z0-9_]*([^)]*) *//
s/^%[a-z0-9_][a-z0-9_]* *//
/^$/d
'"$extra" "$@"
}

# Write an output debuginfo file list based on given input file lists.
filtered_list()
{
  local out="$1"
  shift
  test $# -gt 0 || return
  grep -F -f <(filelist_debugfiles 's,^.*$,/usr/lib/debug&.debug,' "$@") \
  	-x $LISTFILE >> $out
  sed -n -f <(filelist_debugfiles 's/[\\.*+#]/\\&/g
h
s,^.*$,s# &$##p,p
g
s,^.*$,s# /usr/lib/debug&.debug$##p,p
' "$@") "$LINKSFILE" | append_uniq "$out"
}

# Write an output debuginfo file list based on an grep -E -style regexp.
pattern_list()
{
  local out="$1" ptn="$2"
  test -n "$ptn" || return
  grep -E -x -e "$ptn" "$LISTFILE" >> "$out"
  sed -n -r "\#^$ptn #s/ .*\$//p" "$LINKSFILE" | append_uniq "$out"
}

#
# When given multiple -o switches, split up the output as directed.
#
i=0
while ((i < nout)); do
  > ${outs[$i]}
  filtered_list ${outs[$i]} ${lists[$i]}
  pattern_list ${outs[$i]} "${ptns[$i]}"
  grep -Fvx -f ${outs[$i]} "$LISTFILE" > "${LISTFILE}.new"
  mv "${LISTFILE}.new" "$LISTFILE"
  ((++i))
done
if ((nout > 0)); then
  # Now add the right %dir lines to each output list.
  (cd "${RPM_BUILD_ROOT}"; find usr/lib/debug -type d) |
  sed 's#^.*$#\\@^/&/@{h;s@^.*$@%dir /&@p;g;}#' |
  LC_ALL=C sort -ur > "${LISTFILE}.dirs.sed"
  i=0
  while ((i < nout)); do
    sed -n -f "${LISTFILE}.dirs.sed" "${outs[$i]}" | sort -u > "${outs[$i]}.new"
    cat "${outs[$i]}" >> "${outs[$i]}.new"
    mv -f "${outs[$i]}.new" "${outs[$i]}"
    ((++i))
  done
  sed -n -f "${LISTFILE}.dirs.sed" "${LISTFILE}" | sort -u > "${LISTFILE}.new"
  cat "$LISTFILE" >> "${LISTFILE}.new"
  mv "${LISTFILE}.new" "$LISTFILE"
fi
sed -i -e "s|/usr/lib/debug|/usr/share/debug|g" $LISTFILE
sed -i -e "s|/usr/src/debug|/usr/share/debug/src|g" $LISTFILE
